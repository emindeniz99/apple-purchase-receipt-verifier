//! The exported-symbol allowlist (docs/rust-core/SURFACE.md §9): the shared
//! library exports exactly the functions of `exported-symbols.txt`, so no
//! Rust, OpenSSL or libc symbol leaks into a caller's namespace, and a new
//! export is a deliberate change to that file and to the header.
//!
//! Reads the built library's dynamic symbol table with `nm`, which must be
//! on PATH (binutils on Linux, the Xcode tools on macOS). Other platforms
//! have no test here; `rust/bindings/CI-NOTES.md` says so.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The cdylib `cargo test` built beside this test binary.
///
/// Where cargo puts either is its build layout, which changes between
/// releases: the test binary was `target/<profile>/deps/<name>` with the
/// library beside it, and cargo's newer build-dir layout puts each unit in
/// a directory of its own under `target/<profile>/build/`. So the library
/// is looked for, not placed: under the directory of this build's profile
/// (the test binary's ancestor just below the directory holding cargo's
/// `CACHEDIR.TAG`), anywhere, the newest copy. `cargo test` does not copy
/// the library up to `target/<profile>/`, but a `cargo build` does, and
/// the newest copy is the one this run built or a later build of it.
fn library() -> PathBuf {
    let name = if cfg!(target_os = "macos") {
        "libapple_purchase_receipt_verifier_ffi.dylib"
    } else {
        "libapple_purchase_receipt_verifier_ffi.so"
    };
    let exe = std::env::current_exe().expect("the test binary's path");
    let root = exe
        .ancestors()
        .find(|dir| dir.join("CACHEDIR.TAG").is_file())
        .unwrap_or_else(|| panic!("no cargo target directory above {}", exe.display()));
    let profile = exe
        .ancestors()
        .find(|dir| dir.parent() == Some(root))
        .expect("the test binary sits below the target directory");
    let mut found = Vec::new();
    find(profile, name, 8, &mut found);
    found
        .into_iter()
        .max_by_key(|(_, modified)| *modified)
        .map(|(path, _)| path)
        .unwrap_or_else(|| {
            panic!(
                "the cdylib is not built: no {name} under {}",
                profile.display()
            )
        })
}

/// Every file called `name` under `dir`, at most `depth` levels down, with
/// its modification time.
fn find(dir: &Path, name: &str, depth: usize, found: &mut Vec<(PathBuf, std::time::SystemTime)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() && depth > 0 {
            find(&path, name, depth - 1, found);
        } else if kind.is_file() && entry.file_name() == name {
            if let Ok(modified) = entry.metadata().and_then(|meta| meta.modified()) {
                found.push((path, modified));
            }
        }
    }
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
