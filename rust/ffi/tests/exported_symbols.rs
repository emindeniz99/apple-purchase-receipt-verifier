//! The exported-symbol allowlist (docs/rust-core/SURFACE.md §9): the shared
//! library exports exactly the functions of `exported-symbols.txt`, so no
//! Rust, OpenSSL or libc symbol leaks into a caller's namespace, and a new
//! export is a deliberate change to that file and to the header.
//!
//! Reads the built library's dynamic symbol table with `nm`, which must be
//! on PATH (binutils on Linux, the Xcode tools on macOS). Other platforms
//! have no test here; `rust/ffi/CI-NOTES.md` says so.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::path::PathBuf;
use std::process::Command;

fn library() -> PathBuf {
    // The test binary is target/<profile>/deps/<name>; cargo puts the
    // cdylib of this package in target/<profile>/.
    let exe = std::env::current_exe().expect("the test binary's path");
    let profile = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile>");
    let name = if cfg!(target_os = "macos") {
        "libapple_purchase_receipt_verifier_ffi.dylib"
    } else {
        "libapple_purchase_receipt_verifier_ffi.so"
    };
    let path = profile.join(name);
    assert!(
        path.is_file(),
        "{} is not built: run `cargo build -p apple-purchase-receipt-verifier-ffi` first",
        path.display()
    );
    path
}

#[test]
fn the_library_exports_exactly_the_allowlist() {
    let args: &[&str] = if cfg!(target_os = "macos") {
        &["-g", "-U", "-j"]
    } else {
        &["-D", "--defined-only", "--format=just-symbols"]
    };
    let output = Command::new("nm")
        .args(args)
        .arg(library())
        .output()
        .expect("nm is on PATH");
    assert!(
        output.status.success(),
        "nm failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut exported: Vec<String> = String::from_utf8(output.stdout)
        .expect("nm prints UTF-8")
        .lines()
        .map(|symbol| symbol.trim().trim_start_matches('_').to_owned())
        .filter(|symbol| !symbol.is_empty())
        .collect();
    exported.sort();
    exported.dedup();
    let mut allowed: Vec<String> = include_str!("../exported-symbols.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    allowed.sort();
    assert_eq!(exported, allowed, "the shared library's exports");
}
