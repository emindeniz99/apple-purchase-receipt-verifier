//! The only place this crate touches cryptography.
//!
//! Everything here is public-key verification of attacker-supplied bytes:
//! there is no private key in the process, nothing secret to leak, and no
//! oracle to time. The RSA modular exponentiation and the two ECDSA curves
//! come from `RustCrypto`; the parsing of every input to them is this crate's
//! own, so no third-party parser ever decides what a key or a signature is.
//!
//! No code path here — or anywhere in the crate — reads an operating-system
//! trust store, opens a socket, or fetches a CRL, an OCSP response or an AIA
//! URL. Revocation is disabled by design (`PLAN.md` D12).

use crate::asn1::{decode_oid, parse_exact, tag, Tlv};
use crate::cms::digest_for;
use crate::x509::{Certificate, OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION};
use digest::Digest;
use md5::Md5;
use rsa::{BigUint, Pkcs1v15Sign, Pss, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

/// A message digest this crate can compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// MD5: accepted only because a pinned chain signed it (Q15).
    Md5,
    /// SHA-1 — Apple's legacy receipt chain and CMS digest.
    Sha1,
    /// SHA-224
    Sha224,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl DigestAlgorithm {
    /// The digest of `data`.
    #[must_use]
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            DigestAlgorithm::Md5 => Md5::digest(data).to_vec(),
            DigestAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            DigestAlgorithm::Sha224 => Sha224::digest(data).to_vec(),
            DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn pkcs1v15_padding(self) -> Pkcs1v15Sign {
        match self {
            DigestAlgorithm::Md5 => Pkcs1v15Sign::new::<Md5>(),
            DigestAlgorithm::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
            DigestAlgorithm::Sha224 => Pkcs1v15Sign::new::<Sha224>(),
            DigestAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
            DigestAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
            DigestAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
        }
    }

    fn pss_padding(self, salt_length: usize) -> Pss {
        match self {
            DigestAlgorithm::Md5 => Pss::new_with_salt::<Md5>(salt_length),
            DigestAlgorithm::Sha1 => Pss::new_with_salt::<Sha1>(salt_length),
            DigestAlgorithm::Sha224 => Pss::new_with_salt::<Sha224>(salt_length),
            DigestAlgorithm::Sha256 => Pss::new_with_salt::<Sha256>(salt_length),
            DigestAlgorithm::Sha384 => Pss::new_with_salt::<Sha384>(salt_length),
            DigestAlgorithm::Sha512 => Pss::new_with_salt::<Sha512>(salt_length),
        }
    }
}

/// The widest RSA modulus this crate will verify under.
///
/// Apple's largest published root is RSA-4096; the headroom bounds what an
/// attacker-supplied certificate can cost to check.
const MAX_RSA_BITS: usize = 8192;

/// How a signature is checked: what the `signatureAlgorithm` OID names,
/// with the digest the chain walk or the `SignerInfo` supplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// RSASSA-PKCS1-v1_5.
    Pkcs1(DigestAlgorithm),
    /// RSASSA-PSS, with its digest and salt length from the parameters.
    Pss(DigestAlgorithm, usize),
    /// ECDSA with a DER `ECDSA-Sig-Value`.
    Ecdsa(DigestAlgorithm),
}

const OID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const OID_MGF1: &str = "1.2.840.113549.1.1.8";

/// The certificate `signatureAlgorithm` OIDs the chain walk accepts: every
/// one the `RustCrypto` crates this crate is built on can verify (owner,
/// 2026-09-27, Q14: whatever the crypto library verifies under the pinned
/// chain, no stricter list). MD2 and DSA are absent because no crate here
/// implements them, not by policy.
///
/// The weak digests (MD5, SHA-1) are on the list because these signatures
/// are on certificates a pinned root vouched for, directly or through a
/// certificate it vouched for, never on attacker-chosen data; Apple's own
/// legacy receipt chain is signed with SHA-1.
fn certificate_signature_scheme(oid: &str, params: Option<&[u8]>) -> Option<Scheme> {
    match oid {
        "1.2.840.113549.1.1.4" => Some(Scheme::Pkcs1(DigestAlgorithm::Md5)),
        "1.2.840.113549.1.1.5" => Some(Scheme::Pkcs1(DigestAlgorithm::Sha1)),
        "1.2.840.113549.1.1.14" => Some(Scheme::Pkcs1(DigestAlgorithm::Sha224)),
        "1.2.840.113549.1.1.11" => Some(Scheme::Pkcs1(DigestAlgorithm::Sha256)),
        "1.2.840.113549.1.1.12" => Some(Scheme::Pkcs1(DigestAlgorithm::Sha384)),
        "1.2.840.113549.1.1.13" => Some(Scheme::Pkcs1(DigestAlgorithm::Sha512)),
        OID_RSASSA_PSS => pss_scheme(params?),
        "1.2.840.10045.4.1" => Some(Scheme::Ecdsa(DigestAlgorithm::Sha1)),
        "1.2.840.10045.4.3.1" => Some(Scheme::Ecdsa(DigestAlgorithm::Sha224)),
        "1.2.840.10045.4.3.2" => Some(Scheme::Ecdsa(DigestAlgorithm::Sha256)),
        "1.2.840.10045.4.3.3" => Some(Scheme::Ecdsa(DigestAlgorithm::Sha384)),
        "1.2.840.10045.4.3.4" => Some(Scheme::Ecdsa(DigestAlgorithm::Sha512)),
        _ => None,
    }
}

/// `RSASSA-PSS-params` (RFC 4055 3.1): the hash, MGF1 over that same hash
/// (the only mask the `rsa` crate implements), the salt length and the
/// trailer field 1, each with its DEFAULT when absent.
fn pss_scheme(params: &[u8]) -> Option<Scheme> {
    let node = parse_exact(params).ok()?;
    if node.tag != tag::SEQUENCE {
        return None;
    }
    let mut digest = DigestAlgorithm::Sha1;
    let mut mask_digest = DigestAlgorithm::Sha1;
    let mut salt_length = 20usize;
    let mut last_tag = None;
    for field in node.children() {
        // Each field at most once, in order.
        if last_tag.is_some_and(|last| field.tag <= last) {
            return None;
        }
        last_tag = Some(field.tag);
        let inner = field.child(0)?;
        match field.tag {
            tag::CONTEXT_0 => digest = hash_algorithm(inner)?,
            tag::CONTEXT_1 => {
                let oid = inner.child(0).filter(|n| n.tag == tag::OID)?;
                if decode_oid(oid.contents)? != OID_MGF1 {
                    return None;
                }
                mask_digest = hash_algorithm(inner.child(1)?)?;
            }
            tag::CONTEXT_2 => salt_length = small_integer(inner)?,
            tag::CONTEXT_3 => {
                if small_integer(inner)? != 1 {
                    return None;
                }
            }
            _ => return None,
        }
    }
    (digest == mask_digest).then_some(Scheme::Pss(digest, salt_length))
}

fn hash_algorithm(node: &Tlv<'_>) -> Option<DigestAlgorithm> {
    if node.tag != tag::SEQUENCE {
        return None;
    }
    let oid = node.child(0).filter(|n| n.tag == tag::OID)?;
    digest_for(oid.contents)
}

fn small_integer(node: &Tlv<'_>) -> Option<usize> {
    if node.tag != tag::INTEGER
        || node.contents.len() > 2
        || node.contents.first().is_none_or(|first| *first >= 0x80)
    {
        return None;
    }
    Some(
        node.contents
            .iter()
            .fold(0usize, |value, byte| value << 8 | usize::from(*byte)),
    )
}

/// The curves this crate verifies under, and their field size in bytes.
///
/// P-256 carries every App Store JWS leaf; P-384 carries Apple Root CA - G3.
/// A key on any other curve fails closed everywhere it is reached. On the
/// JWS path it is reached first by `parse_x5c_certificate`, which refuses
/// the certificate outright (`INVALID_CERTIFICATE`); elsewhere the signature
/// simply does not verify and the chain through it is `UNTRUSTED_CHAIN`.
pub(crate) fn curve_field_size(oid: &str) -> Option<usize> {
    match oid {
        "1.2.840.10045.3.1.7" => Some(32), // prime256v1 / P-256
        "1.3.132.0.34" => Some(48),        // secp384r1 / P-384
        _ => None,
    }
}

fn rsa_public_key(spki_bits: &[u8]) -> Option<RsaPublicKey> {
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let node = parse_exact(spki_bits).ok()?;
    if node.tag != tag::SEQUENCE {
        return None;
    }
    let modulus = node.child(0).filter(|n| n.tag == tag::INTEGER)?;
    let exponent = node.child(1).filter(|n| n.tag == tag::INTEGER)?;
    // A negative INTEGER is not a modulus. Reject rather than reinterpret.
    if modulus.contents.first().is_some_and(|b| *b >= 0x80)
        || exponent.contents.first().is_some_and(|b| *b >= 0x80)
    {
        return None;
    }
    let n = BigUint::from_bytes_be(modulus.contents);
    let e = BigUint::from_bytes_be(exponent.contents);
    RsaPublicKey::new_with_max_size(n, e, MAX_RSA_BITS).ok()
}

/// RSASSA-PKCS1-v1_5 verification with the given digest.
///
/// Any failure — an unparseable key, a key that is not RSA, a malformed
/// signature — is a `false`, never a panic and never an error type of its
/// own.
#[must_use]
pub fn verify_rsa_pkcs1(
    spki_bits: &[u8],
    algorithm: DigestAlgorithm,
    signature: &[u8],
    data: &[u8],
) -> bool {
    let Some(key) = rsa_public_key(spki_bits) else {
        return false;
    };
    let hashed = algorithm.digest(data);
    key.verify(algorithm.pkcs1v15_padding(), &hashed, signature)
        .is_ok()
}

/// ECDSA verification over a fixed-width `r ‖ s` signature.
#[must_use]
pub fn verify_ecdsa_raw(
    curve_oid: &str,
    key_bits: &[u8],
    algorithm: DigestAlgorithm,
    raw_signature: &[u8],
    data: &[u8],
) -> bool {
    let Some(field_size) = curve_field_size(curve_oid) else {
        return false;
    };
    if raw_signature.len() != field_size * 2 {
        return false;
    }
    let prehash = algorithm.digest(data);
    // `verify_prehash` is the ECDSA operation, not a shortcut around one:
    // Apple's own JWS test PKI signs with ecdsa-with-SHA384 over P-256 keys,
    // where the digest is wider than the field and SEC1 truncation applies.
    // A fixed `verify(msg)` would refuse that chain.
    if field_size == 32 {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bits) else {
            return false;
        };
        let Ok(signature) = p256::ecdsa::Signature::from_slice(raw_signature) else {
            return false;
        };
        key.verify_prehash(&prehash, &signature).is_ok()
    } else {
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        let Ok(key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bits) else {
            return false;
        };
        let Ok(signature) = p384::ecdsa::Signature::from_slice(raw_signature) else {
            return false;
        };
        key.verify_prehash(&prehash, &signature).is_ok()
    }
}

/// ES256, the JWS payload signature: a P-256 key, SHA-256, and a raw 64-byte
/// `r ‖ s` signature per RFC 7515.
#[must_use]
pub fn verify_es256(key_bits: &[u8], signature: &[u8], data: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    verify_ecdsa_raw(
        "1.2.840.10045.3.1.7",
        key_bits,
        DigestAlgorithm::Sha256,
        signature,
        data,
    )
}

/// `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` as the
/// fixed-width `r ‖ s` form.
fn ecdsa_der_to_raw(der: &[u8], field_size: usize) -> Option<Vec<u8>> {
    let node = parse_exact(der).ok()?;
    if node.tag != tag::SEQUENCE || node.children().len() != 2 {
        return None;
    }
    let r = node.child(0).filter(|n| n.tag == tag::INTEGER)?;
    let s = node.child(1).filter(|n| n.tag == tag::INTEGER)?;
    let mut out = Vec::with_capacity(field_size * 2);
    out.extend_from_slice(&fixed_width(r.contents, field_size)?);
    out.extend_from_slice(&fixed_width(s.contents, field_size)?);
    Some(out)
}

fn fixed_width(integer: &[u8], field_size: usize) -> Option<Vec<u8>> {
    let mut start = 0;
    while start + 1 < integer.len() && integer.get(start) == Some(&0x00) {
        start += 1;
    }
    let value = integer.get(start..)?;
    if value.len() > field_size {
        return None;
    }
    let mut out = vec![0u8; field_size];
    let offset = field_size - value.len();
    out.get_mut(offset..)?.copy_from_slice(value);
    Some(out)
}

/// Whether `cert`'s signature was made by `issuer`'s key, under the
/// algorithm `cert` names.
///
/// Any failure — an unknown algorithm, a key/algorithm mismatch, a malformed
/// signature — is a `false`. This is the whole cryptographic content of the
/// chain walk.
#[must_use]
pub fn verify_certificate_signature(cert: &Certificate, issuer: &Certificate) -> bool {
    certificate_signature_scheme(
        cert.signature_algorithm_oid(),
        cert.signature_algorithm_params(),
    )
    .is_some_and(|scheme| verify_scheme(scheme, issuer, cert.signature_value(), cert.tbs_bytes()))
}

/// A CMS `SignerInfo` signature under `signer`'s key. RSASSA-PSS when the
/// `signatureAlgorithm` says so, with the hash its parameters name;
/// otherwise the key type decides, RSASSA-PKCS1-v1_5 for an RSA key and
/// ECDSA for a key on a curve this crate implements, with the
/// `SignerInfo`'s digest. Any other key, or any malformed signature, is a
/// `false`.
#[must_use]
pub fn verify_signer_signature(
    signer: &Certificate,
    digest: DigestAlgorithm,
    signature_algorithm: (&str, Option<&[u8]>),
    signature: &[u8],
    data: &[u8],
) -> bool {
    let scheme = match signature_algorithm {
        (OID_RSASSA_PSS, params) => match params.and_then(pss_scheme) {
            Some(scheme) => scheme,
            None => return false,
        },
        _ => match signer.public_key_algorithm_oid() {
            OID_RSA_ENCRYPTION => Scheme::Pkcs1(digest),
            OID_EC_PUBLIC_KEY => Scheme::Ecdsa(digest),
            _ => return false,
        },
    };
    verify_scheme(scheme, signer, signature, data)
}

// --- the key-use seam ------------------------------------------------------

std::thread_local! {
    /// The SPKIs of the keys used to check a signature on this thread, while
    /// [`keys_used_during`] is recording; `None` otherwise, which costs one
    /// thread-local read per signature check.
    static KEYS_USED: core::cell::RefCell<Option<Vec<Vec<u8>>>> =
        const { core::cell::RefCell::new(None) };
}

/// Notes that the key `spki` is about to check a signature.
pub(crate) fn record_key_use(spki: &[u8]) {
    KEYS_USED.with(|keys| {
        if let Some(keys) = keys.borrow_mut().as_mut() {
            keys.push(spki.to_vec());
        }
    });
}

/// Runs `body` and returns, beside its result, the SPKI of every key used to
/// check a signature on this thread meanwhile. The seam the tests use to
/// assert that no key a pinned root did not vouch for is ever used, rather
/// than inferring it from timing.
pub fn keys_used_during<R>(body: impl FnOnce() -> R) -> (R, Vec<Vec<u8>>) {
    let previous = KEYS_USED.with(|keys| keys.borrow_mut().replace(Vec::new()));
    let result = body();
    let used = KEYS_USED.with(|keys| core::mem::replace(&mut *keys.borrow_mut(), previous));
    (result, used.unwrap_or_default())
}

fn verify_scheme(scheme: Scheme, key: &Certificate, signature: &[u8], data: &[u8]) -> bool {
    record_key_use(key.spki());
    match scheme {
        Scheme::Pkcs1(digest) => {
            key.public_key_algorithm_oid() == OID_RSA_ENCRYPTION
                && verify_rsa_pkcs1(key.public_key_bits(), digest, signature, data)
        }
        Scheme::Pss(digest, salt_length) => {
            key.public_key_algorithm_oid() == OID_RSA_ENCRYPTION
                && rsa_public_key(key.public_key_bits()).is_some_and(|rsa| {
                    rsa.verify(
                        digest.pss_padding(salt_length),
                        &digest.digest(data),
                        signature,
                    )
                    .is_ok()
                })
        }
        Scheme::Ecdsa(digest) => {
            if key.public_key_algorithm_oid() != OID_EC_PUBLIC_KEY {
                return false;
            }
            let Some(curve) = key.public_key_curve_oid() else {
                return false;
            };
            let Some(field_size) = curve_field_size(curve) else {
                return false;
            };
            let Some(raw) = ecdsa_der_to_raw(signature, field_size) else {
                return false;
            };
            verify_ecdsa_raw(curve, key.public_key_bits(), digest, &raw, data)
        }
    }
}

/// Constant-time byte equality. Lengths are public and compared first.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::{rsa_public_key, MAX_RSA_BITS};
    use rsa::BigUint;

    /// `RSAPublicKey` DER for an all-ones odd modulus of `bytes` bytes.
    fn rsa_key_der(bytes: usize, exponent: &[u8]) -> Vec<u8> {
        fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
            let mut out = vec![tag, 0x82];
            let length = u16::try_from(contents.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(contents);
            out
        }
        let mut modulus = vec![0x00];
        modulus.resize(bytes + 1, 0xFF);
        tlv(0x30, &[tlv(0x02, &modulus), tlv(0x02, exponent)].concat())
    }

    /// The cost cap on an attacker's key: a modulus over [`MAX_RSA_BITS`]
    /// is refused as it is read, before any arithmetic, and so is an
    /// exponent over the `rsa` crate's 2^33 - 1. The Java port needed a
    /// walk-order fix because its key decoding ran a primality test that
    /// took seconds for a 16384-bit modulus; here such a key never gets
    /// that far.
    #[test]
    fn an_oversized_rsa_key_is_refused_before_any_arithmetic() {
        let largest_exponent = [0x01, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(rsa_public_key(&rsa_key_der(MAX_RSA_BITS / 8, &largest_exponent)).is_some());
        assert!(rsa_public_key(&rsa_key_der(16384 / 8, &largest_exponent)).is_none());
        assert!(rsa_public_key(&rsa_key_der(
            MAX_RSA_BITS / 8,
            &[0x02, 0x00, 0x00, 0x00, 0x01]
        ))
        .is_none());
    }

    /// Every receipt pays for three RSA-2048 verifies (two chain links and
    /// the CMS signature), and they are most of a small receipt's cost.
    /// `num-bigint-dig` does that arithmetic in 32-bit limbs unless `rsa`'s
    /// `u64_digit` feature is on, which `default-features = false` silently
    /// drops, and the 32-bit build takes about 1.7x as long per verify. The
    /// limb width is visible through `get_limb`: with 64-bit limbs 2^32 fits
    /// in limb 0, with 32-bit limbs limb 0 is zero.
    ///
    /// The `u64::from` is a no-op only while the test passes; it is what lets
    /// the test still compile, and fail, when the limbs are `u32`.
    #[allow(clippy::useless_conversion)]
    #[test]
    fn rsa_arithmetic_uses_64_bit_limbs() {
        let two_pow_32 = BigUint::from(1u64 << 32);
        assert_eq!(
            u64::from(two_pow_32.get_limb(0)),
            1u64 << 32,
            "rsa's u64_digit feature is off; restore it in Cargo.toml"
        );
    }
}
