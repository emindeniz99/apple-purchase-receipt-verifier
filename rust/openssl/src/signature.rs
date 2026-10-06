//! Digests and the JWS signature, through rust-openssl's safe EVP and
//! ECDSA wrappers.

use crate::{drain_errors, init, Certificate};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;

/// ES256 (RFC 7515 section 3.4): SHA-256 and ECDSA with the certificate's
/// key, which must be on P-256, over `message`, with the 64-byte `r || s`
/// signature. Any other key, curve or signature length is a `false`.
#[must_use]
pub fn verify_es256(leaf: &Certificate, raw_signature: &[u8], message: &[u8]) -> bool {
    init();
    if raw_signature.len() != 64 {
        return false;
    }
    let verified = (|| {
        let key = leaf.x509().public_key().ok()?;
        let ec = key.ec_key().ok()?;
        if ec.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Some(false);
        }
        let (r, s) = raw_signature.split_at_checked(32)?;
        let signature = EcdsaSig::from_private_components(
            BigNum::from_slice(r).ok()?,
            BigNum::from_slice(s).ok()?,
        )
        .ok()?;
        #[cfg(feature = "test-seams")]
        crate::keys::record(&key);
        let digest = openssl::sha::sha256(message);
        signature.verify(&digest, &ec).ok()
    })();
    drain_errors();
    verified == Some(true)
}

/// SHA-256.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    init();
    openssl::sha::sha256(data)
}
