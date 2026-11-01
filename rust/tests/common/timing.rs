//! Whether this run checks wall-clock bounds.
//!
//! A bound on elapsed time measures the machine as much as the code. In a
//! debug build on a loaded CI runner such bounds have failed with nothing
//! wrong in the code (docs/rust-core/REVIEW-LOG.md, R3-F3). So a plain
//! `cargo test` checks every verdict and every deterministic cost record
//! (the keys a signature check used, the full CMS decodes), and leaves
//! out only the comparison with the clock. `APRV_TIMING_ASSERTS=1` turns
//! that comparison on; CI's `rust` job runs the timed suites that way in a
//! step of its own, one test at a time, so the bounds still gate a merge.
//!
//! A file of its own so the conformance harness, which does not take the
//! rest of `common`, can include it by path.

/// True when `APRV_TIMING_ASSERTS` is `1`.
pub fn enabled() -> bool {
    std::env::var_os("APRV_TIMING_ASSERTS").is_some_and(|value| value == "1")
}
