#!/bin/sh
# Spike only (2026-09-27). Upstream testing facts for Wasmi v2.0.0, read
# from the tag's own files (fetch.sh clones it) and from OSS-Fuzz and
# Wasmtime on the same day.
#   SCRATCH=... scripts/upstream_facts.sh > results/upstream-testing.txt
set -eu
: "${SCRATCH:?}"
G="$SCRATCH/secrev/wasmi-git"
echo "# read $(date -u +%FT%TZ) from wasmi v2.0.0 ($(git -C "$G" rev-parse HEAD))"

echo "## fuzz targets (fuzz/Cargo.toml [[bin]] names) and differential oracles"
grep -E '^name = ' "$G/fuzz/Cargo.toml" | sed 's/^/  /'
ls "$G/crates/fuzz/src/oracle" | sed 's/^/  oracle: /'
echo "## fuzz module generator: imports allowed by wasm-smith config"
grep -n 'max_imports\|max_memories' "$G/crates/fuzz/src/config.rs" | sed 's/^/  config.rs:/'
echo "## execute target: how imports are resolved (empty Linker => any module with imports fails to instantiate and is skipped)"
grep -n 'Linker::new\|instantiate_and_start\|define\|func_wrap' "$G/fuzz/fuzz_targets/execute.rs" | sed 's/^/  execute.rs:/'
grep -n 'Linker::new\|instantiate_and_start\|define\|func_wrap' "$G/crates/fuzz/src/oracle/wasmi.rs" | sed 's/^/  oracle\/wasmi.rs:/'
echo "## fuzz compilation modes chosen per input"
grep -n 'CompilationMode::' "$G/crates/fuzz/src/config.rs" | sed 's/^/  config.rs:/'

echo "## CI (.github/workflows/rust.yml): fuzz and miri jobs"
grep -n "fuzz_target: \[\|max_total_time\|cargo miri nextest run\|cargo miri test\|schedule\|cron" "$G/.github/workflows/rust.yml" | sed 's/^/  rust.yml:/'
grep -n 'cron\|miri' "$G/.github/workflows/miri.yml" | head -8 | sed 's/^/  miri.yml:/'

echo "## spec testsuite harness (crates/wast/tests/mod.rs)"
echo "  submodule pins: $(git -C "$G" ls-tree HEAD crates/wast/tests/ | awk '$2=="commit"{print $4"@"$3}' | tr '\n' ' ')"
echo "  test files listed: $(grep -c 'fn [a-z0-9_]*("' "$G/crates/wast/tests/mod.rs")"
for p in multi-memory memory64 tail-call extended-const custom-page-sizes relaxed-simd wide-arithmetic simd_; do
  printf '  %-18s %s entries\n' "$p" "$(grep -c "$p" "$G/crates/wast/tests/mod.rs")"
done
grep -n 'compilation_mode(' "$G/crates/wast/tests/mod.rs" | sed 's/^/  mod.rs:/'
grep -n '#\[ignore' "$G/crates/wast/tests/mod.rs" | sed 's/^/  mod.rs:/'
echo "  modes: $(grep -nE '^mod [a-z_0-9]+ \{' "$G/crates/wast/tests/mod.rs" | sed 's/ {//; s/.*mod //' | tr '\n' ' ')"

echo "## OSS-Fuzz"
for f in project.yaml build.sh; do
  code=$(curl -sS -o "$SCRATCH/secrev/ossfuzz-$f" -w '%{http_code}' "https://raw.githubusercontent.com/google/oss-fuzz/master/projects/wasmi/$f")
  echo "  projects/wasmi/$f: HTTP $code"
done
grep -E 'sanitizers|address|libfuzzer|main_repo' "$SCRATCH/secrev/ossfuzz-project.yaml" | sed 's/^/    /'
grep -E 'Copyright|cargo .*fuzz build' "$SCRATCH/secrev/ossfuzz-build.sh" | sed 's/^/    /'

echo "## Wasmtime's differential fuzzer and the wasmi version it pins (main branch)"
code=$(curl -sS -o /dev/null -w '%{http_code}' https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/crates/fuzzing/src/oracles/diff_wasmi.rs)
echo "  crates/fuzzing/src/oracles/diff_wasmi.rs: HTTP $code"
curl -sS https://raw.githubusercontent.com/bytecodealliance/wasmtime/main/Cargo.lock | grep -A1 '^name = "wasmi"$' | sed 's/^/  Cargo.lock: /'

echo "## published binaries (release.yml builds the CLI only; the C-API artifact crate is publish = false)"
grep -n '^name:' "$G/.github/workflows/release.yml" | sed 's/^/  release.yml:/'
grep -n 'publish' "$G/crates/c_api/artifact/Cargo.toml" | sed 's/^/  c_api\/artifact\/Cargo.toml:/'
