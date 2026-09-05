#![no_main]

//! The X.509 walk. A certificate that parses is then read through every
//! accessor, because the accessors slice the input again — an offset kept
//! from parsing is exactly the kind of state a mutated length can leave
//! wrong.

use apple_purchase_receipt_verifier::x509::Certificate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(certificate) = Certificate::from_der(data) else {
        return;
    };
    let _ = certificate.der();
    let _ = certificate.tbs_bytes();
    let _ = certificate.serial_number();
    let _ = certificate.issuer_der();
    let _ = certificate.subject_der();
    let _ = certificate.spki();
    let _ = certificate.public_key_algorithm_oid();
    let _ = certificate.public_key_curve_oid();
    let _ = certificate.public_key_bits();
    let _ = certificate.signature_algorithm_oid();
    let _ = certificate.signature_value();
    let _ = certificate.key_usage();
    let _ = certificate.subject_key_id();
    let _ = certificate.authority_key_id();
    let _ = certificate.authority_cert_serial();
    let _ = certificate.has_extension("1.2.840.113635.100.6.11.1");
    let _ = certificate.valid_at(0);
    let _ = certificate.valid_at(i64::MAX);
    let _ = certificate.valid_at(i64::MIN);
});
