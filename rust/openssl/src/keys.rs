//! A record of the public keys this crate builds to check a signature, for
//! tests that assert no key a pinned root did not vouch for is ever used.

use openssl::pkey::{PKeyRef, Public};
use std::cell::RefCell;

std::thread_local! {
    /// The `SubjectPublicKeyInfo` DER of every key used to check a
    /// signature on this thread while [`keys_used_during`] records; `None`
    /// otherwise, which costs one thread-local read per signature check.
    static KEYS_USED: RefCell<Option<Vec<Vec<u8>>>> = const { RefCell::new(None) };
}

/// Notes that `key` is about to check a signature.
pub(crate) fn record(key: &PKeyRef<Public>) {
    KEYS_USED.with(|keys| {
        if let Ok(mut keys) = keys.try_borrow_mut() {
            if let Some(keys) = keys.as_mut() {
                keys.push(key.public_key_to_der().unwrap_or_default());
            }
        }
    });
    crate::drain_errors();
}

/// Runs `body` and returns, beside its result, the `SubjectPublicKeyInfo`
/// DER (as `i2d_PUBKEY` writes it) of every key this crate used to check a
/// signature on this thread meanwhile: certificate links, CMS signatures
/// and ES256 alike. `X509_verify_cert` checks the signatures of the path it
/// is given once more, with the keys of that path; those uses are not
/// listed.
pub fn keys_used_during<R>(body: impl FnOnce() -> R) -> (R, Vec<Vec<u8>>) {
    /// Puts the previous record back when dropped, so a panic in `body`
    /// that is caught does not leave every later signature check
    /// recording.
    struct Restore(Option<Vec<Vec<u8>>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            KEYS_USED.with(|keys| keys.replace(previous));
        }
    }
    let restore = Restore(KEYS_USED.with(|keys| keys.replace(Some(Vec::new()))));
    let result = body();
    let used = KEYS_USED.with(RefCell::take);
    drop(restore);
    (result, used.unwrap_or_default())
}
