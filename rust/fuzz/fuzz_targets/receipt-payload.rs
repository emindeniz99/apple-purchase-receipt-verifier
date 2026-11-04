#![no_main]

//! The receipt payload decoder (`receipt_payload.rs`: the attribute SET,
//! each in-app purchase, the strings, integers and dates) on arbitrary
//! signed-content bytes, through the `test-seams` hook that runs the
//! verifier's own decode with no envelope in front of it. The whole-receipt
//! targets cannot get here: random bytes never carry a signature a pinned
//! root vouches for, and only the creation date is read before one passes.
//!
//! Seeds are the eContent of the fixture receipts, extracted by
//! `derive-seeds.py` when `run.sh` starts this target.
//!
//! What must hold, beyond no panic:
//! - a refusal is `UNREADABLE_PAYLOAD`: the signer signed these bytes, so
//!   the verifier never blames the client (`MALFORMED`) for them;
//! - a decoded payload's `to_json()`, which the crate writes by hand and
//!   every binding hands out, parses as a JSON object;
//! - the creation date read before the signature, the instant the chain is
//!   judged at, is the creation date the decoded payload reports. The two
//!   are read by different code (the first attribute 12 before, the
//!   first-copy rule after); if they disagreed, a receipt would be judged
//!   at an instant other than the one it states.

use apple_purchase_receipt_verifier::__internal::read_receipt_content;
use apple_purchase_receipt_verifier::Reason;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (created, read) = read_receipt_content(data);
    match read {
        Ok(payload) => {
            let json = payload.to_json();
            let value: serde_json::Value = serde_json::from_str(&json)
                .unwrap_or_else(|err| panic!("to_json wrote text that is not JSON: {err}"));
            assert!(
                value.is_object(),
                "to_json wrote JSON that is not an object"
            );
            assert_eq!(
                created, payload.receipt_creation_date_ms,
                "the chain instant differs from the creation date the payload reports"
            );
        }
        Err(failure) => assert_eq!(
            failure.reason(),
            Reason::UnreadablePayload,
            "signed content was refused as something other than unreadable: {failure}"
        ),
    }
});
