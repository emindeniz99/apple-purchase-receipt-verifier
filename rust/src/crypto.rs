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

use crate::asn1::{parse_exact, tag};
use crate::x509::{Certificate, OID_EC_PUBLIC_KEY, OID_RSA_ENCRYPTION};
use digest::Digest;
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

/// A message digest this crate can compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// SHA-1 — Apple's legacy receipt chain and CMS digest.
    Sha1,
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
            DigestAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
            DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
            DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
            DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn pkcs1v15_padding(self) -> Pkcs1v15Sign {
        match self {
            DigestAlgorithm::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
            DigestAlgorithm::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
            DigestAlgorithm::Sha384 => Pkcs1v15Sign::new::<Sha384>(),
            DigestAlgorithm::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
        }
    }
}

/// The widest RSA modulus this crate will verify under.
///
/// Apple's largest published root is RSA-4096; the headroom bounds what an
/// attacker-supplied certificate can cost to check.
const MAX_RSA_BITS: usize = 8192;

/// The certificate `signatureAlgorithm` OIDs the chain walk accepts.
///
/// `sha1WithRSAEncryption` is on the list because Apple's own legacy receipt
/// chain is signed that way — the Apple Inc. Root CA and the intermediates
/// under it. Dropping it would drop legacy receipt support, not harden
/// anything: these signatures are on certificates Apple issued years ago and
/// pinned here by their root, not on attacker-chosen data.
fn certificate_signature_algorithm(oid: &str) -> Option<(bool, DigestAlgorithm)> {
    match oid {
        "1.2.840.113549.1.1.5" => Some((true, DigestAlgorithm::Sha1)),
        "1.2.840.113549.1.1.11" => Some((true, DigestAlgorithm::Sha256)),
        "1.2.840.113549.1.1.12" => Some((true, DigestAlgorithm::Sha384)),
        "1.2.840.113549.1.1.13" => Some((true, DigestAlgorithm::Sha512)),
        "1.2.840.10045.4.3.2" => Some((false, DigestAlgorithm::Sha256)),
        "1.2.840.10045.4.3.3" => Some((false, DigestAlgorithm::Sha384)),
        "1.2.840.10045.4.3.4" => Some((false, DigestAlgorithm::Sha512)),
        _ => None,
    }
}

/// The curves this crate verifies under, and their field size in bytes.
///
/// P-256 carries every App Store JWS leaf; P-384 carries Apple Root CA - G3.
/// A key on any other curve fails closed: the signature simply does not
/// verify, so a chain through it is `INVALID_CHAIN`.
fn curve_field_size(oid: &str) -> Option<usize> {
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
    let Some((rsa, algorithm)) = certificate_signature_algorithm(cert.signature_algorithm_oid())
    else {
        return false;
    };
    if rsa {
        if issuer.public_key_algorithm_oid() != OID_RSA_ENCRYPTION {
            return false;
        }
        return verify_rsa_pkcs1(
            issuer.public_key_bits(),
            algorithm,
            cert.signature_value(),
            cert.tbs_bytes(),
        );
    }
    if issuer.public_key_algorithm_oid() != OID_EC_PUBLIC_KEY {
        return false;
    }
    let Some(curve) = issuer.public_key_curve_oid() else {
        return false;
    };
    let Some(field_size) = curve_field_size(curve) else {
        return false;
    };
    let Some(raw) = ecdsa_der_to_raw(cert.signature_value(), field_size) else {
        return false;
    };
    verify_ecdsa_raw(
        curve,
        issuer.public_key_bits(),
        algorithm,
        &raw,
        cert.tbs_bytes(),
    )
}

/// Constant-time byte equality. Lengths are public and compared first.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}
