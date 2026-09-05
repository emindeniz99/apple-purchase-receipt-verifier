#![no_main]

//! The CMS `SignedData` walk, plus the two signed-attribute readers a
//! parsed structure feeds. This is the walk the probe that preceded the port
//! found an out-of-bounds panic in by mutating a genuine receipt, so it gets
//! its own target rather than only being reached through `verify_receipt`.

use apple_purchase_receipt_verifier::cms::{
    find_message_digest_attribute, parse_cms, signed_attrs_signed_bytes,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(cms) = parse_cms(data) else {
        return;
    };
    if let Some(signed_attrs) = &cms.signer_info.signed_attrs {
        let _ = find_message_digest_attribute(signed_attrs);
        let _ = signed_attrs_signed_bytes(signed_attrs);
    }
});
