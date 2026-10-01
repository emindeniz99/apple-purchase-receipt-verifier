# Can a time-zone crate replace the hand-written US Pacific code?

Measured 2026-10-01. This note backs docs/rust-core/DECISIONS.md R38: the
core takes its calendar and the `America/Los_Angeles` offset behind every
`_pst` date from `jiff` instead of `rust/src/datetime.rs`'s own rules.

## Question

Until 2026-10-01 the core wrote the US Pacific rules out by hand: a
42-entry table for 1918-1966, closed-form rules from 1967, and Howard
Hinnant's civil-date arithmetic. Its module doc gave two reasons for not
using a crate: `chrono-tz` compiles the whole IANA database in, and
`jiff` reads `/usr/share/zoneinfo`, which a `FROM scratch` image and the
Wasm module do not have. Do those reasons still hold, which crate would
do the job, at what size, and does any of them disagree with the
hand-written rules?

## Versions

Rust 1.98.1, target wasm32-wasip1. chrono 0.4.45 with chrono-tz 0.10.4
(tzdata 2025b); jiff 0.2.37 with jiff-tzdb 0.1.8 (tzdata 2026c); tz-rs
0.7.3 with tzdb_data 0.2.5 (tzdata 2026b); time 0.3.55 with time-tz 2.0.0;
the system TZif file is tzdata 2025b.

## Method

Each option is a tiny wasm binary (`sizes/<variant>/`) that renders one
instant with the repo's `format_civil`; only the offset function differs.
The profile is the module's `[profile.wasm]` (opt-level 3, LTO, one
codegen unit, `panic = "abort"`) plus `strip`, since `build.sh` strips the
module's name section. `stub` always answers PST; `hand` is the repo code
(`common/pacific.rs`). A native differential (`diff/`) compares every
option with `pacific_offset_seconds` at every minute from 1900-01-01 to
2100-01-01 (105 million instants) and at the second before and the second
of 986 transition probes (`rust/tests/data/pacific-transitions.txt` and
the TZif file's transitions).

## Results

Sizes from `build-sizes.sh` (opt-level s in brackets), crate counts from
`cargo tree -e normal,build --target wasm32-wasip1`, disagreements from
`run-diff.sh`. Both scripts were rerun from this folder on 2026-10-01 and
gave the same numbers.

| Option | .wasm bytes | vs hand | crates compiled | disagreements |
|---|---|---|---|---|
| stub | 56,177 (55,049) | -1,743 | 0 | n/a |
| hand (repo) | 57,920 (56,607) | 0 | 0 | reference |
| tzdb_data 0.2.5 + tz-rs 0.7.3 | 60,994 (59,894) | +3,074 | 2 | 0 |
| chrono 0.4.45 + chrono-tz 0.10.4, filtered | 65,894 (64,723) | +7,974 | 6 runtime + 9 build (regex, phf_codegen, parse-zoneinfo...) | 0 |
| same, `Tz` opaque | 66,271 | +8,351 | same | 0 |
| chrono-tz unfiltered, constant `Tz` | 65,928 (64,723) | +8,008 | 6 | 0 |
| chrono-tz unfiltered, `Tz` opaque | 935,251 (949,675) | +877,331 | 6 | 0 |
| time 0.3.55 + time-tz 2.0.0 | 68,640 | +10,720 | 39 (wasm-bindgen, BSD-3-Clause) | 0 |
| tz-rs + `include_bytes!` TZif | 88,880 | +30,960 | 1 | 0 |
| jiff 0.2.37 `tz::get!` (feature `static`) | 95,335 (81,000) | +37,415 | 8 (2 runtime; proc-macro, syn at build) | 0 |
| jiff `TimeZone::posix("PST8PDT,M3.2.0,M11.1.0")` | 328,052 | +270,132 | 2 | 19.8 M minutes: every DST season 1900-2006 |
| jiff `TimeZone::tzif` + `include_bytes!` | 361,365 | +303,445 | 2 | 0 |

## Findings

- The hand-written table and rules agree with five IANA-derived sources
  (chrono-tz, jiff-tzdb, the system TZif through jiff and through tz-rs,
  tzdb_data, time-tz) at every probed instant from 1900 to 2100.
- The module doc's reasons were partly stale. LTO drops chrono-tz's unused
  zones when the zone is a constant, and jiff embeds one zone at compile
  time (`tz::get!`, feature `static`) and reads no file at run time.
- chrono-tz's filter works (`filter-by-regex` with
  `CHRONO_TZ_TIMEZONE_FILTER`), but only the shell environment reaches its
  build script. An `[env]` entry in `.cargo/config.toml` is silently
  ignored when cargo runs with `--manifest-path` from another directory,
  which is how `build.sh` runs: 935 KB against 66 KB from the same crate.
  A crates.io consumer never gets the filter.
- A POSIX rule alone is wrong for every year before 2007; only a TZif
  source carries the history.

## Decision

**jiff adopted, owner 2026-10-01.** The reason is that the project does
not maintain calendar code: the rules, the table and the civil-date
arithmetic were the one part of the core that encoded law rather than
Apple's policy, and a change in US daylight-saving law would have been a
code change here. jiff is not the smallest option; tz-rs with tzdb_data
is 34 KB smaller in the spike. jiff gives the calendar as well as the
zone from one crate, its `static` feature needs no
build-time environment and no file, and it builds without `std` or
`alloc` on wasm32-wasip1.

## Costs, measured on the real module

`rust/src/datetime.rs` on jiff (option B of R38: jiff's answers taken
as they are, no cycle arithmetic), built with
`tools/wasm-toolchain.sh` and `rust/bindings/abi/build.sh`:

| | aprv.wasm bytes | gzip -9 |
|---|---|---|
| main at 7f2ea42 (rebuilt here: the committed module's SHA-256, 4e9d2d85...) | 2,764,700 | 920,521 |
| with jiff | 2,813,436 | 930,273 |
| delta | +48,736 (+1.8%) | +9,752 |
| the same, printing with jiff's `strftime` instead of `format!` | 3,050,396 | 993,296 |
| the same, civil time from `DateTime::checked_add(SignedDuration)` and `strftime` | 3,053,495 | 994,808 |

- `strftime` alone costs 236,960 bytes, so `format_civil` prints jiff's
  civil fields with `format!`; a test holds that to `strftime`'s bytes
  over the whole year range. `DateTime` arithmetic costs about as much
  again, so the civil time comes from `Offset::to_datetime` instead.
- `rust/Cargo.lock` gains 12 packages. Two link into the module: `jiff`
  and `jiff-core`. `jiff-static`, `jiff-tzdb` (the database the macro
  reads), and the already-present `proc-macro2`, `quote` and `syn` run
  only at build time. `portable-atomic` and `portable-atomic-util` are
  for targets without atomics and are not built for any target the
  project ships; `defmt`, `thiserror` and a second `bitflags` are
  optional dependencies the lockfile lists and no build enables. All
  are MIT or dual MIT; `cargo deny check` passes.
- `datetime.rs` goes from 486 to 179 lines. The receipt-date grammar stays
  hand-checked, because it is the contract with Java and jiff's parsers
  accept more.
- jiff's last timestamp, 9999-12-30T22:00:00Z, is 26 hours before the
  grammar's last second. Those seconds are carried in the offset jiff
  renders with (it allows ±25:59:59 for this), and their Pacific offset is
  the one at jiff's last second, exact because 9999-12-30 and -31 are PST.
- jiff looks a timestamp up by its second truncated toward zero, so
  before 1970 the last millisecond ahead of a transition took the new
  offset. The core looks up the floored second. The spike's differential
  probed whole seconds only and could not see this.
- What changes: before 1883-11-18T20:00:00Z the Pacific rendering is local
  mean time (−07:52:58), as Java's `ZoneId` gives, where the hand-written
  code answered PST; and the endpoint answers a clock outside -9999 to
  9999-12-31T23:59:59Z with `{"status":21009}` instead of a date with a
  five-digit year.
- The core's own differential (`rust/tests/datetime.rs`, ignored test)
  holds the jiff code to the hand-written code at 182,918,657 instants:
  every minute from 1883-11-18T20:00Z to 2100, every transition, and
  every hour to 9999-12-31T23:59:59Z. 0 disagreements.

## Limits

- The spike's sizes are deltas in a small binary; inside `aprv.wasm` the
  jiff code costs +48,736 bytes, not +37,415, because the core also takes
  its civil-date conversion from jiff.
- Agreement is checked from 1883 to 2100 minute by minute and to the end
  of 9999 hourly. For future years both codes apply today's rule, as the
  database itself does.
- tzdata changes reach the module only when `jiff-tzdb` publishes and the
  lockfile takes it. A future change to US daylight-saving law is a
  dependency bump and a module rebuild.
