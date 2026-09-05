#![no_main]

//! The bounded ASN.1 reader, on its own. Every other target reaches it
//! through a structure walk; this one hands it arbitrary bytes directly so
//! a length or depth bug shows up without a CMS or certificate shape around
//! it. The invariant is the module's own: one well-formed value or an
//! `Asn1Error`, never a panic.

use apple_purchase_receipt_verifier::asn1::parse_exact;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_exact(data);
});
