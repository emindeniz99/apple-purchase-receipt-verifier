#![no_main]

//! The JWS payload reader (`jws.rs` `read_payload` over `json.rs`: strict
//! UTF-8, a whole JSON object, the `signedDate` and `receiptCreationDate`
//! conversion, the environment in its three places) on arbitrary decoded
//! payload bytes, through the `test-seams` hook that runs the verifier's
//! own read with no header, chain or signature in front of it. The
//! `verify-transaction` target reaches this read only for inputs whose
//! header and three `x5c` certificates still parse, and a mutation there
//! lands in base64url, not in the JSON.
//!
//! Seeds are the payload segments of the fixture JWSs, decoded by
//! `derive-seeds.py` when `run.sh` starts this target.
//!
//! What must hold, beyond no panic:
//! - a refusal is `UNREADABLE_PAYLOAD`, as for a payload whose signature
//!   passed;
//! - an accepted payload's `json()` is the input, byte for byte: the
//!   verifier returns the payload exactly as signed.

use apple_purchase_receipt_verifier::__internal::read_jws_payload;
use apple_purchase_receipt_verifier::Reason;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match read_jws_payload(data) {
        Ok(payload) => assert_eq!(
            payload.json().as_bytes(),
            data,
            "the payload returned is not the payload signed"
        ),
        Err(failure) => assert_eq!(
            failure.reason(),
            Reason::UnreadablePayload,
            "a signed payload was refused as something other than unreadable: {failure}"
        ),
    }
});
