#!/usr/bin/env bash
# The C ABI suite of the rust-ffi job, on any of its three operating
# systems:
#
#   .github/scripts/rust-ffi-suite.sh
#
# Run from the repository root, after Node is set up. ci.yml calls it from
# rust-ffi (one leg per OS) and, on a pull request, from macos-wrappers,
# which runs the macOS leg; one script keeps the two from drifting. The
# Linux-only checks (the 1.85.0 floor and the generated header) stay steps
# of rust-ffi, since they are not platform-specific.
set -euo pipefail

group() {
  if [[ -n "${in_group:-}" ]]; then echo "::endgroup::"; fi
  echo "::group::$*"
  in_group=1
}

group "toolchain"
rustup toolchain install stable --profile minimal --component rustfmt,clippy

# rust/ffi is a member of the rust/ workspace: rust/Cargo.lock is its
# lockfile and the library lands in rust/target/<profile>. --locked turns
# "cargo quietly rewrote the lockfile" into a failed job rather than an
# unnoticed bump.
group "cargo build"
(cd rust/ffi && cargo build --locked)
group "cargo fmt --check"
(cd rust/ffi && cargo fmt --check)
group "cargo clippy"
(cd rust/ffi && cargo clippy --locked --all-targets -- -D warnings)
# Layer 1: null pointers, non-UTF-8 input, rejected configurations, and the
# panic guard every exported symbol runs its body inside.
group "cargo test"
(cd rust/ffi && cargo test --locked)

# Layer 2, the primary one: fixtures/cases.json driven through the ABI from
# C++17. A passing run is the evidence that the compiled-toolchain path
# works: header compiles as C++, symbols link, answers match the vectors
# every other port answers.
group "flatten the shared vectors for a compiler"
node tools/gen-cases-manifest.mjs rust/ffi/target/manifest
group "build the C++ consumers"
cmake -S rust/ffi/examples/cpp -B rust/ffi/target/cppbuild
cmake --build rust/ffi/target/cppbuild --config Debug
group "C++ conformance over the C ABI"
rust/ffi/target/cppbuild/bin/aprv_conformance rust/ffi/target/manifest
group "the README example"
rust/ffi/target/cppbuild/bin/aprv_example \
  fixtures/generated/jws-root.der \
  fixtures/generated/transaction.jws \
  fixtures/generated/receipt-b64/01-genuine.txt

# Layer 3: the same vectors again from a language with no compiler in the
# loop, checking the nested field paths the C++ harness cannot reach. This
# is what "any FFI-capable language" means, tested.
interpreter=python3
command -v python3 >/dev/null 2>&1 || interpreter=python
group "ctypes conformance over the C ABI"
(cd rust/ffi && "$interpreter" tests/conformance.py ../target/debug)
group "the README example, from Python"
(cd rust/ffi && "$interpreter" examples/python/example.py ../target/debug)
echo "::endgroup::"
