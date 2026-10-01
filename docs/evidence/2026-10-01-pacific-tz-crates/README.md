# Pacific time-zone crates spike

The sources behind `../2026-10-01-pacific-tz-crates.md`. `$SPIKE` is this
folder, `$REPO` the repository root, `$SCRATCH` any directory outside the
repository; every build goes to `$SCRATCH`.

| Path | Question |
|---|---|
| `common/pacific.rs` | The hand-written Pacific code as `rust/src/datetime.rs` carried it before jiff, comments dropped (lines 18-19, 42-122 and 148-304 of that file at 7f2ea42); `rust/tests/hand_written_datetime/` keeps the same code as the core's test reference |
| `sizes/<variant>/` | One wasm32-wasip1 binary per option; size delta against `stub` (PST always) and `hand` (the repo code) |
| `sizes/chrono-tz-*-dyn` | Same, with the `Tz` value hidden from the optimiser (`black_box`), as after a name lookup |
| `sizes/chrono-tz-filtered-config` | Does a `.cargo/config.toml` `[env]` filter apply under `--manifest-path`? |
| `build-sizes.sh` | Builds every variant, prints `.wasm` bytes, gzip bytes and lock packages; `OPT=s` for opt-level s |
| `diff/` + `run-diff.sh` | Every candidate's offset against `pacific_offset_seconds`, at each minute 1900-2100 plus every transition and the second before it, from `$REPO/rust/tests/data/pacific-transitions.txt` and from the system TZif file |

The TZif variants and the differential read
`data/America_Los_Angeles.tzif`, a copy of the system's
`/usr/share/zoneinfo/America/Los_Angeles` (tzdata 2025b here). It is a
binary, so it is not committed; copy it in first.

Reproduce (Rust 1.98.1 with the wasm32-wasip1 target):

```sh
export SCRATCH=<a directory outside the repository>
mkdir -p "$SPIKE/data"
cp /usr/share/zoneinfo/America/Los_Angeles "$SPIKE/data/America_Los_Angeles.tzif"
"$SPIKE/build-sizes.sh"           # opt-level 3: the repo's wasm profile + strip
OPT=s "$SPIKE/build-sizes.sh"
"$SPIKE/run-diff.sh"              # about 45 s
# The [env] filter in .cargo/config.toml, from another directory and from its own:
cargo build --release --target wasm32-wasip1 --manifest-path "$SPIKE/sizes/chrono-tz-filtered-config/Cargo.toml" --target-dir "$SCRATCH/cfg"   # 935 KB
env --chdir="$SPIKE/sizes/chrono-tz-filtered-config" cargo build --release --target wasm32-wasip1 --target-dir "$SCRATCH/cfg2"                   # 66 KB
rm -rf "$SPIKE/data"
```

The core's own differential, against the code that replaced this one, is
`the_pacific_offset_matches_the_hand_written_rules_from_1883_to_9999`
in `$REPO/rust/tests/datetime.rs`
(`cargo test --release --test datetime -- --ignored`).
