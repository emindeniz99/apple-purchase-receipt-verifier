//! Counts the panics a call raised, the ones the library contained
//! included.
//!
//! `Verifier` runs every verification inside `catch_unwind` and answers a
//! panic with a reason (`MALFORMED` before a signature has verified), so
//! a test's own `catch_unwind` around a verify call never fires and a
//! "never panics" test cannot judge by the outcome. A panic hook runs when
//! the panic starts, before the unwind reaches any `catch_unwind`, so it
//! sees a contained panic too. The count is per thread: the tests of one
//! binary run on parallel threads (and the conformance harness reuses its
//! worker threads), and a test elsewhere that panics on purpose must not
//! be charged to the one asking. Each caller reads a difference, never
//! the running total.
//!
//! A file of its own so the conformance harness, which does not take the
//! rest of `common`, can include it by path.

use std::cell::Cell;
use std::sync::Once;

thread_local! {
    static PANICS: Cell<usize> = const { Cell::new(0) };
}

/// Runs `body` and returns, beside its result, how many panics started on
/// this thread meanwhile, contained or not.
pub fn panics_during<R>(body: impl FnOnce() -> R) -> (R, usize) {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            // try_with: a panic while the thread's locals are being torn
            // down must still reach the previous hook.
            let _ = PANICS.try_with(|count| count.set(count.get() + 1));
            previous(info);
        }));
    });
    let before = PANICS.with(Cell::get);
    let result = body();
    (result, PANICS.with(Cell::get) - before)
}
