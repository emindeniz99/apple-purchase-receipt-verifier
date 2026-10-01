# Replacing the core's JSON reader with serde_json (2026-10-01)

**Question.** Can `rust/src/json.rs`, the hand-written bounded reader for
the JWS header, the JWS payload and the `verifyReceipt` request body, give
way to `serde_json`, which the core already depends on? This feeds the
owner's rule that a well-maintained library replaces hand-written code.

**Versions.** serde_json 1.0.151 (default features, no `preserve_order`),
Rust 1.98.1, wasi-sdk 34.0, base commit `7f2ea42`. Java: jackson-core
2.22.3 with `BoundedJson`'s constraints. Code and commands are in
`2026-10-01-json-serde/`.

## Two variants

- **A, `Map<String, Value>`.** Each document is read into a
  `serde_json::Value` tree.
- **B, `BTreeMap<String, &RawValue>`.** Each document is read into a map
  from name to raw value text, with serde_json's `raw_value` feature.
  Values nobody reads are checked against the grammar and skipped without
  being built. `alg`, `x5c`, `signedDate` and `receipt-data` are then
  parsed from their raw text.

`json.rs` drops from 370 lines of code to 25 (A) or 35 (B).

## Rule by rule

| Rule | json.rs | Java (Jackson) | serde_json A | serde_json B |
|---|---|---|---|---|
| Nesting | 64 | 64 | refuses at 128 (`remaining_depth: u8 = 128`; 127 is read). No public API lowers it; `disable_recursion_limit` (feature `unbounded_depth`) only removes it | none on skipped values: `ignore_value` is iterative and costs 1 heap byte per level |
| Name length | 50,000 UTF-16 units | 50,000 | none | none |
| Number length | 1,000 digits | 1,000 | none; out of `f64` range is an error (`1e400`, an integer of 310 or more digits) | none on skipped values |
| Endpoint: first value, rest unread | yes | yes | `StreamDeserializer::next` | same |
| JWS: only whitespace after the object | yes | yes | `from_str` (space, tab, LF, CR) | same |
| Duplicate names | last wins | last wins | last wins (`Map::insert`; with `preserve_order`, `IndexMap::insert` keeps the first position and the last value) | last wins (`BTreeMap::insert`) |
| Lone surrogate escape | U+FFFD | kept in the Java `String` | error | error in a name or a value that is read; not examined in a skipped value |
| Control characters, bad escapes, leading zeros, `+`, `NaN`, trailing commas, comments, BOM | refused | refused | refused | refused, skipped values included |
| Integer outside `i64` as `signedDate` | none | none | `u64` none; past `u64` it is read as an `f64`, so −9223372036854775809 gives `i64::MIN` | same |
| Float precision | correctly rounded | correctly rounded | best effort unless `float_roundtrip` is on | same |

`arbitrary_precision` would keep each number's text and drop the out-of-range
error, but it changes `Value` for every crate in the build. Neither variant
uses it.

## Tests

`cargo test --workspace`: base 700 of 700 pass. A: 694 of 701. B: 694 of
701 (core package, then the other members; those 49 all pass). Each variant
fails 5 shared cases and the two hand-written depth tests in
`tests/input_size_caps.rs`.

| Case | Before | A | B |
|---|---|---|---|
| `endpoint/request-body-nested-65-deep-answers-21002` | 21002 | 0 | 0 |
| `signed-data/reject-a-header-nested-65-deep` | MALFORMED | ok | ok |
| `signed-data/unreadable-payload-nested-65-deep` | UNREADABLE_PAYLOAD | ok | ok |
| `signed-data/reject-a-header-member-name-of-50001-characters` | MALFORMED | ok | ok |
| `signed-data/accept-a-header-number-of-1000-digits` | ok | MALFORMED | ok |
| `signed-data/reject-a-header-number-of-1001-digits` | MALFORMED | MALFORMED | ok |

Every changed case is class (b): a bound or shape Apple never emits. None
is class (a): the signed fixtures carry the same signature as before, and
`reject-an-unsigned-payload-nested-65-deep` stays INVALID_SIGNATURE. The
endpoint case is a genuine receipt inside an envelope with extra nesting,
so the receipt is still the one that was signed. No change is class (c).

## Cost before any signature check

Inputs are capped at 3,145,728 bytes for a request body and at 262,144
bytes for a JWS, which is 196,608 bytes per decoded segment. Times and
peak heap, natively, best of 5 (`cost-results.md`):

| 3 MiB body | old | A | B |
|---|---|---|---|
| `[{"":0},…]` | 11 ms, 240 B | 205 ms, 301 MB | 7 ms, 465 B |
| `[{"":{"":…}},…]`, 63 deep | 11 ms, 240 B | 252 ms, 396 MB | 6 ms, 521 B |
| 321,563 distinct members | 26 ms, 46 MB | 89 ms, 36 MB | 83 ms, 26 MB |
| a 3 MiB number, name or string | ≤ 4 ms, ≤ 3.1 MB | ≤ 3.4 ms, ≤ 3.1 MB | ≤ 1.3 ms, ≤ 3.1 MB |
| 1.5 M levels deep | refused | refused | 5 ms, 3.1 MB |

A builds a tree of unsigned input at up to 126 times its size: 396 MB for
one request, or 25 MB for one JWS segment. A pooled Wasm instance keeps the
memory it grows. MAX_NAME_LENGTH and MAX_NUMBER_LENGTH prevented no blow-up:
both libraries read a long name, number or string in linear time and copy
it at most once. B's worst case costs 26 MB (the old reader's: 46 MB) and
83 ms (the old reader's: 41 ms).

## Size and dependencies

| Module (`build.sh`, stripped) | Bytes | gzip -9 |
|---|---:|---:|
| base (same SHA-256 as the committed module, `4e9d2d85…`) | 2,764,700 | 920,521 |
| A | 2,750,801 | 918,394 |
| B | 2,758,418 | 918,944 |

`cargo build --locked` succeeded for each one: Cargo.lock still has 131
packages. B adds one serde_json feature and no new package.

## Verdict

Use B. A turns a parser bound into a 126-times memory amplification. B
needs none of the three hand-written bounds and costs less memory than the
old reader. The five cases above become `oneOf`. The endpoint expectation
has no `oneOf` form, so its case needs a schema addition. Java keeps
`BoundedJson` as it is.

**Where this stops holding.** Costs were measured on x86-64. On wasm32 a
`Value` is smaller, but A's shape stays the same.

**Outcome.** Variant B is the core since 2026-10-01 (DECISIONS.md R40).
Built on main after the jiff change (R38), the module went from 2,813,436
to 2,807,151 bytes (gzip -9: 930,272 to 929,641), with no new lockfile
package.
The merged code parses `signedDate` from its raw text with the reference
conversion (an integer must fit an `i64`; a fraction or an exponent is
truncated within that range; anything else is no instant), so the
"integer outside `i64`" row above describes the prototype, not the core.
