# How well the Rust core is tested: coverage and mutants

Date: 2026-10-31.

**Question.** The Java implementation was hardened with line and branch
coverage and mutation testing. How much of the Rust core (`rust/src`)
and its OpenSSL adapter (`rust/openssl/src`) do their own test suites
execute, and how many small changes to that code would those suites fail
to notice? The answer is a list of missing tests, ranked by what a wrong
verdict there would cost, for the next round of test work.

**Answer.** The suites execute 95.9 % of the lines, 95.4 % of the code
regions and 85.8 % of the branches of the two crates. Of 786 mutants,
636 were caught, 58 missed, none timed out and 92 did not compile. 17 of
the 58 change a verdict or a reason under some input; the rest are
`Debug`/`Display` output, a panic message, leaks, unreachable guards or
equivalent rewrites. Nothing found accepts a forged receipt or JWS today. The gaps
worth tests are listed under "Triage", most important first.

## Versions

- Main at 13a5d03, on the branch `test/core-coverage-mutants`.
- Rust 1.99.1 (`rust/rust-toolchain.toml`), LLVM 23.1.1, debug profile.
  Branch coverage is still unstable in rustc, so `coverage.sh` sets
  `RUSTC_BOOTSTRAP=1` on that stable compiler rather than switching to a
  nightly whose code generation differs.
- cargo-llvm-cov 0.9.1 and cargo-mutants 27.1.0, built from crates.io with
  that toolchain (`install-tools.sh`).
- OpenSSL 4.0.3 from `openssl-src` 400.0.2+4.0.3: vendored for coverage;
  for mutants the same build's install directory, linked with
  `OPENSSL_NO_VENDOR=1` so each cargo-mutants worker skips the compile.
- One Linux x86-64 container: 4 vCPUs (Intel Xeon, 2.1 GHz), 15 GiB,
  shared with other agents' builds (load average 9 to 13 during the
  mutants runs).

## Method

The scripts and their README are in
[`2026-10-31-core-coverage-mutants/`](2026-10-31-core-coverage-mutants/).

- **Coverage** (`coverage.sh`): `cargo llvm-cov --branch` over
  `-p apple-purchase-receipt-verifier -p aprv-openssl`, so every unit and
  integration test of both crates runs, the 449 conformance tests from
  `fixtures/cases.json` among them. The report keeps `rust/src` and
  `rust/openssl/src` only. `uncovered.py` then lists every region no copy
  of the code ran and every branch side never taken, summing the counts
  over monomorphised copies and over the two builds of `aprv-openssl`
  (with and without `test-seams`). The C templates `payload.c` and
  `envelope.c` and OpenSSL itself are compiled by `cc` and are not
  measured.
- **Mutants** (`mutants.sh`): `cargo mutants --list` counted 786 mutants
  in the two crates. A clean build took 40 s and one test run 9 s, so
  the whole set fit well inside three hours; the security-critical files
  ran first (`scoped`, 640 mutants: receipt, JWS, path, base64, JSON,
  payload, endpoint, verifier, roots and the adapter's CMS, certificate,
  path, signature, walk, payload, envelope, item and lib), then the rest
  (`rest`, 146: dates, errors, config, environment, the crate root, the
  key-use seam). Every mutant was tested by both crates' suites
  (`--test-package` both), three workers, a 120 s test timeout.

Two adjustments were needed, both recorded in the scripts:

- `envelope_bounds`'
  `a_tiny_entry_flood_costs_what_junk_of_its_size_costs` is skipped in
  the mutants runs. It compares two wall-clock costs and failed the
  unmutated baseline in a debug build on the loaded machine (178 ms
  against a bound of 174 ms). It failed under coverage too, in two of
  three runs. Its property is also pinned without a clock by
  `a_million_tiny_set_entries_are_refused_by_the_node_budget_first`.
- `openssl/tests/isolation.rs` reads `../../fixtures` from the adapter's
  directory and ignores `APRV_FIXTURES_DIR`, so `mutants.sh` links
  `fixtures/` beside cargo-mutants' copies of `rust/`.

## Coverage

From `coverage-summary.txt`. Lines and branches are covered/total.

| File | Lines | Regions | Branches |
|---|---|---|---|
| openssl/src/certificate.rs | 194/208 (93.3 %) | 94.7 % | 32/44 |
| openssl/src/cms.rs | 249/279 (89.2 %) | 90.4 % | 39/58 |
| openssl/src/envelope.rs | 43/43 | 100 % | 10/10 |
| openssl/src/item.rs | 42/42 | 100 % | 2/2 |
| openssl/src/keys.rs | 22/23 | 97.7 % | 3/4 |
| openssl/src/lib.rs | 27/31 | 88.4 % | 2/2 |
| openssl/src/path.rs | 217/223 (97.3 %) | 95.4 % | 26/32 |
| openssl/src/payload.rs | 99/101 | 97.5 % | 22/24 |
| openssl/src/signature.rs | 26/27 | 86.8 % | 3/4 |
| openssl/src/walk.rs | 161/170 (94.7 %) | 87.6 % | 66/76 |
| src/base64.rs | 56/56 | 100 % | 2/2 |
| src/config.rs | 37/51 | 66.2 % | 2/2 |
| src/datetime.rs | 108/108 | 96.9 % | 22/22 |
| src/endpoint.rs | 185/189 | 96.7 % | 22/22 |
| src/environment.rs | 20/20 | 100 % | none |
| src/error.rs | 81/88 | 86.3 % | 1/2 |
| src/json.rs | 128/128 | 99.6 % | 14/14 |
| src/jws.rs | 234/244 | 94.9 % | 22/22 |
| src/lib.rs | 15/23 | 71.4 % | none |
| src/path.rs | 184/194 (94.8 %) | 96.0 % | 42/52 |
| src/receipt.rs | 178/181 | 98.3 % | 20/20 |
| src/receipt_payload.rs | 635/635 | 100 % | 20/20 |
| src/roots.rs | 105/105 | 100 % | 12/12 |
| src/verifier.rs | 138/150 | 91.3 % | 4/6 |
| **Total** | **3184/3319 (95.9 %)** | **95.4 %** | **388/452 (85.8 %)** |

The misses in `config.rs`, `error.rs`, `lib.rs`, `verifier.rs:144`,
`jws.rs:100-114`, `cms.rs:60-64,124-128` and `certificate.rs:18-20` are
`Debug` and `Display` impls, a `const fn` evaluated at compile time and
the version getters; they are left out below.

### Uncovered code an untrusted input can reach

Every other uncovered region is in `uncovered.txt`. These are the ones a
receipt, a JWS or an endpoint body can reach, or might:

- `openssl/src/cms.rs:462-463`: a `contentType` signed attribute whose
  first value is not an OBJECT IDENTIFIER. Reached by a receipt that
  embeds Apple's public chain and carries a SignerInfo of its own with
  signed attributes; the check runs after the chain and before the
  signature.
- `openssl/src/cms.rs:498-502`: `BIO_set_md` failing, for a
  `digestAlgorithm` OpenSSL resolves by NID but cannot fetch from the
  default provider (a legacy digest), if 4.0 still resolves one. Same
  reach as above.
- `openssl/src/signature.rs:20-22`: a JWS leaf whose key is RSA, or EC
  on a curve other than P-256. Needs a leaf a pinned anchor issued, so a
  caller's own anchors.
- `src/path.rs:267-268`: a JWS intermediate that is not a CA (no
  `cA` TRUE) under a pinned anchor. Caller anchors, as above.
- `src/path.rs:276-277`: a JWS leaf marking critical an extension
  OpenSSL does not process. Caller anchors.
- `src/path.rs:249-254`: an OpenSSL path problem on the JWS path other
  than a missing CA flag, a window or a critical extension. The
  top-down checks before it rule out missing issuers and bad signatures;
  no input is known to reach it.
- `openssl/src/path.rs:83,195`: a second failing per-anchor run, or a
  failing run that is not anchored. A receipt or JWS under two or more
  anchors sharing a subject, none of which passes.
- `openssl/src/walk.rs:309-310`: `children` over an indefinite-length
  value, so a payload SET or attribute SEQUENCE in indefinite form never
  reaches the foreign-chunk check.
- `openssl/src/walk.rs:347`: a chunk with tag number 4 but not of the
  universal class inside a constructed OCTET STRING payload value.
- `openssl/src/walk.rs:354-360`: an indefinite-length constructed OCTET
  STRING as an attribute value or as the Xcode wrap.
- `openssl/src/payload.rs:93,144`: a constructed attribute value of
  another class with tag 4, and the mapping of a foreign chunk in the
  Xcode wrap (the case
  `receipt/unreadable-double-wrap-with-a-foreign-chunk` is refused
  earlier, by the walk).
- `src/datetime.rs:199`: a receipt date whose offset has a non-digit in
  its hours or minutes (`+0x:00`). Kept raw, or the chain is judged at
  the clock.
- `openssl/src/certificate.rs:76` (false side): a PEM anchor block
  OpenSSL refuses, such as an encrypted one. Caller configuration, not
  verification input.
- `src/verifier.rs:120,139`: the stage-to-reason mapping of a panic
  inside verification. No input is known to panic (the fuzz targets and
  `hostile.rs` say so); only a fault-injection seam could reach it.

The rest are guards no input reaches: allocation failures
(`cms.rs:485-493`, `certificate.rs:58-60`), indexes the caller already
bounded (`cms.rs:228-242,260,291,337`), null pointers OpenSSL never
returns (`cms.rs:383,395,424`, `certificate.rs:131,261,269,295-316`,
`path.rs:363`), trailing bytes the walk refused first (`cms.rs:187`,
`walk.rs:337`), a TooLong problem ten certificates cannot produce
(`src/path.rs:156`), bad-signature codes after top-down authentication
(`openssl/src/path.rs:391`), and the fallbacks of `receipt.rs:172,176,185`
and `src/path.rs:184,279-288`.

## Mutants

From `mutants-scoped-summary.txt` and `mutants-rest-summary.txt`.
Score is caught / (caught + missed).

| File | Caught | Missed | Unviable | Score |
|---|---|---|---|---|
| openssl/src/certificate.rs | 61 | 7 | 5 | 90 % |
| openssl/src/cms.rs | 65 | 8 | 6 | 89 % |
| openssl/src/envelope.rs | 5 | 0 | 2 | 100 % |
| openssl/src/item.rs | 8 | 2 | 1 | 80 % |
| openssl/src/keys.rs | 1 | 1 | 4 | 50 % |
| openssl/src/lib.rs | 5 | 3 | 0 | 63 % |
| openssl/src/path.rs | 20 | 6 | 6 | 77 % |
| openssl/src/payload.rs | 26 | 4 | 7 | 87 % |
| openssl/src/signature.rs | 7 | 0 | 0 | 100 % |
| openssl/src/walk.rs | 91 | 9 | 3 | 91 % |
| src/base64.rs | 10 | 0 | 0 | 100 % |
| src/config.rs | 7 | 3 | 4 | 70 % |
| src/datetime.rs | 67 | 0 | 0 | 100 % |
| src/endpoint.rs | 35 | 0 | 0 | 100 % |
| src/environment.rs | 8 | 1 | 2 | 89 % |
| src/error.rs | 17 | 1 | 7 | 94 % |
| src/json.rs | 22 | 0 | 0 | 100 % |
| src/jws.rs | 30 | 2 | 7 | 94 % |
| src/lib.rs | 14 | 3 | 6 | 82 % |
| src/path.rs | 33 | 5 | 8 | 87 % |
| src/receipt.rs | 17 | 0 | 7 | 100 % |
| src/receipt_payload.rs | 62 | 0 | 4 | 100 % |
| src/roots.rs | 15 | 0 | 8 | 100 % |
| src/verifier.rs | 10 | 3 | 5 | 77 % |
| **Total** | **636** | **58** | **92** | **91.6 %** |

The scoped run took 38 minutes, the rest 8. No mutant timed out.

One catch is spurious: `openssl/src/certificate.rs:295:27` (`||` to `&&`
in `object_octets`) is equivalent, since OpenSSL never hands back a null
OID body with a non-zero length, and only a timing assertion failed for
it (`hostile.rs`' `unsigned_content_of_tiny_attributes_is_refused_at_a_bounded_cost`,
87 ms against 25 ms). It is the only mutant whose sole failure was a
timing assertion; the logs of the other 635 show a verdict or value
failing.

## Triage

(a) a test that should exist, (b) equivalent or unreachable, (c) a code
smell. Ranked: accepting something forged or unsafe first, then
rejecting something genuine, then the wrong reason. The (a) items are
the work list; no test is written here.

### Unsafe or accept-side

1. **(a) `cms.rs:462-463`, a `contentType` signed attribute whose value is
   not an OID** (coverage). The test: a receipt that embeds Apple's chain
   (or a test chain under caller anchors) with a SignerInfo whose signed
   attributes carry `contentType` as, say, an INTEGER is
   `INVALID_SIGNATURE`. The type check is what keeps the next line from
   reading the union as an `ASN1_OBJECT`; an attacker reaches it with
   Apple's public certificates, and nothing pins it.
2. **(a) `cms.rs:498`, a digest OpenSSL names but cannot initialise**
   (coverage). The test: a SignerInfo whose `digestAlgorithm` is a legacy
   digest (MD4, if 4.0 still resolves it by NID) is `INVALID_SIGNATURE`.
   The comment says that without the check the digest BIO would pass the
   content through undigested; by reading OpenSSL the later
   `CMS_SignerInfo_verify_content` fails too, but no test shows which.
3. **(a) `certificate.rs:282`, a duplicate of an extension other than
   basicConstraints and keyUsage** (4 missed mutants: `extension_oids`
   replaced with an empty or fixed list). The duplicate tests and cases
   all duplicate basicConstraints, which `decodes_if_present` refuses on its own, so
   the duplicate check in `is_readable` is never what refuses. The test:
   an x5c leaf, and a receipt signer, carrying the Apple marker OID twice
   (an extension OpenSSL does not check for duplicates) is
   `INVALID_CERTIFICATE`. Without the check, such a certificate likely
   verifies. A pinned anchor must have signed it, so this is a contract
   gap, not a forgery.
4. **(a) `signature.rs:20-22`, a JWS leaf that is RSA or not on P-256**
   (coverage; no mutant survives, but neither refusal ever runs). The
   test: under caller anchors, a chain whose leaf key is P-384, and one
   whose leaf key is RSA, each signing a 64-byte signature, is
   `INVALID_SIGNATURE`. ES256 only is a documented rule with no test.
5. **(a) `payload.rs:61`, an attribute whose value field is not an OCTET
   STRING** (missed: `||` to `&&` accepts a value of another type, or a
   type that is not an INTEGER). The test: a payload entry
   `SEQUENCE { INTEGER 2, INTEGER 1, INTEGER 5 }` makes the payload
   unreadable (`UNREADABLE_PAYLOAD` after the signature; the clock before
   it). Apple must sign such a payload, so it is parity with Java, not a
   forgery.
6. **(a) `walk.rs:354-365`, constructed OCTET STRING values: indefinite
   length, and a foreign chunk after a good one** (missed: the four
   indefinite-branch arithmetic mutants, and `+=` to `*=` at 365, which
   skips every chunk after the first). The tests: an attribute value, and
   an Xcode wrap, as an indefinite-length constructed OCTET STRING with a
   UTF8String chunk, and a definite one whose UTF8String chunk comes
   second, are each unreadable. `walk.rs:309-310` and `347` (indefinite
   SET, non-universal tag 4) belong with these.
7. **(a) `walk.rs:230-231`, the level count inside a constructed string**
   (missed: `string > 0` to `< 0`, `string + 1` to `- 1` or `* 1`). No
   test nests a constructed chunk inside a constructed string where the
   level matters. The test: a constructed OCTET STRING in a deep `ANY`
   (an unsigned attribute, or a payload entry's fourth field) holding a
   constructed chunk tagged INTEGER, which OpenSSL joins, is accepted as
   OpenSSL accepts it; the mutants refuse it. A parity rule, both ways
   wrong only in detail.

### Reject-side

8. **(a) `openssl/src/path.rs:363`, the anchor waivers** (missed: `waived`
   replaced with `false`). No test has an anchor outside its own validity
   window at the chain instant, without `cA` TRUE, or with a path length
   constraint the path exceeds, so the "trusted by fiat" rule could go
   and every test would pass. The test: under a caller anchor that is
   expired at the chain instant (and one that is not a CA), a genuine
   receipt and a genuine JWS still verify. With the waivers gone a
   receipt would read `INVALID_CERTIFICATE` and a JWS `UNTRUSTED_CHAIN`.
   Apple Root CA's own window ends on 2035-02-09.

### Reason-side

9. **(a) `src/path.rs:252,260`, the order of the JWS path's problems**
   (missed: `p.kind != NotCa` to `==`, `p.depth == depth` to `!=`).
   Coverage agrees: an intermediate that is not a CA (267) and a leaf
   with an unhandled critical extension (276) never occur. The tests,
   under caller anchors: an intermediate that is not a CA is
   `UNTRUSTED_CHAIN`; one that is not a CA and also outside its window
   is `INVALID_CERTIFICATE` (window first); an intermediate with an
   unhandled critical extension and a leaf outside its window is
   `UNTRUSTED_CHAIN` (the intermediate's problems first).
10. **(a) `openssl/src/path.rs:193`, which failing run is reported**
    (missed: `&&` to `||`). The test: under two caller anchors sharing a
    subject, the issuing one second, a chain that is expired at the
    instant is `INVALID_CERTIFICATE`, not the `UNTRUSTED_CHAIN` of the
    wrong anchor's broken link.
11. **(a, low) `src/verifier.rs:173` and the panic mapping** (missed:
    `Stage::message` replaced; coverage: lines 120 and 139 never run).
    Only a seam that panics inside a chosen stage can test it; the
    reasons it maps to are the contract the endpoint statuses rest on.

### Equivalent or unreachable (b)

- `src/path.rs:156` (TooLong arm: unreachable, and the `_` arm gives the
  same reason), `src/path.rs:287` ×2 (shape check after OpenSSL built
  leaf, x5c[1], anchor), `openssl/src/path.rs:134,310` (the `Other`
  code is never read), `cms.rs:266` ×2 (`count < 0` to `== 0` or `<= 0`:
  an empty range gives the same answer), `cms.rs:395`, `cms.rs:485,486,489`
  (allocation failure), `certificate.rs:254` (an out-value always
  written), `walk.rs:309` (`&&` to `||` on input the walk accepted),
  `item.rs:65` (no caller reads the string for BOOLEAN, OBJECT or NULL),
  `config.rs:30` (`builder()` already is `Default::default()`),
  `lib.rs:106` (`>` to `>=` in a max), and `payload.rs:92-94` ×3 (a
  value the guard lets through or stops is refused either way; see the
  smells below).
- `openssl/src/path.rs:253` ×2 (`may_have_issued` replaced with `true`
  or negated): the candidate filter saves `X509_verify_cert` runs and
  changes no verdict, since every anchor then gets a run of its own.
- Leaks with no verdict: `certificate.rs:351` (`free_extension_value`),
  `cms.rs:530` and `item.rs:26` (`Drop` emptied), `lib.rs:91`
  (`drain_errors`). A leak checker (ASan or valgrind over the suite)
  would catch them; the tests do not.
- No verdict at all: the `Debug` impls in `certificate.rs`, `cms.rs`,
  `verifier.rs`, `config.rs` (×2) and `error.rs`, `Display` in
  `environment.rs` and `jws.rs:101,110`, `library_version` and
  `openssl_version` ×2 each, and the key-use seam's `Restore::drop`
  (`keys.rs:38`).

### Code smells (c)

- The early return at `cms.rs:266` is dead weight: the loop below it
  answers the same for a count of -1 or 0.
- `payload.rs:92-94` and `attribute` (`payload.rs:61`) both judge the
  value field's type; the guard's class and form tests decide nothing a
  later check does not.
- `src/path.rs:279-288` and `receipt.rs:172,176,185` are fail-closed
  fallbacks no test can reach without a seam. They are worth keeping;
  they should not be counted as tested.
- `a_tiny_entry_flood_costs_what_junk_of_its_size_costs` has about 2 %
  headroom in a debug build under load, and failed three times here
  without a mutant. A bound on a ratio with more slack, or the counter
  seam alone, would stop it flaking.
- `openssl/tests/isolation.rs` hard-codes `../../fixtures`, while every
  other test honours `APRV_FIXTURES_DIR`. `rust/README.md` says
  `tests/conformance.rs` looks above the crate directory only; it reads
  `APRV_FIXTURES_DIR` too.

## Where this stops holding

- One machine, one day, debug builds, OpenSSL 4.0.3 and the tests at
  13a5d03. A release build or another OpenSSL could take other branches
  inside OpenSSL; the Rust branches counted here would not change.
- Coverage counts only Rust. `payload.c`, `envelope.c` and OpenSSL's own
  code, where most of the parsing happens, are not measured; the
  conformance cases and the fuzz targets are what exercise them.
- cargo-mutants mutates Rust expressions and function bodies only. It
  does not mutate the C templates, constants such as the caps and OIDs,
  or the order of statements, so a score of 100 % for a file says its
  operators and returns are pinned, not that its checks are in the
  right order. Items 9 and 10 are order bugs found only because a
  comparison inside them was mutated.
- The mutants ran with one timing test skipped and others left in on a
  loaded machine. A flaky timing failure can only turn a miss into a
  catch, never the reverse; the logs show it happened once.
- The (b) verdicts rest on reading the code and OpenSSL 4.0.3's
  behaviour, not on a test. Items 2 and 3 say "likely" where the reading
  was not run.
