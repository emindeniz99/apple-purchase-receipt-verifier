# Contributing

One product, two implementations, eight wrappers. The Rust core in `rust/`
holds every verification decision; it is compiled once to `aprv.wasm`, and
the Node, Go, Python, Ruby, Swift, .NET, Java `-wasm` and PHP packages run
that one module. `java/` is a second, independent implementation over
BouncyCastle, kept in step with the core by the shared cases in
`fixtures/cases.json`. `aprv-server` (`rust/server/`) runs the module in
its own process, and `rust/ffi/` is the C ABI over the core.

A behaviour change lands in the core, the Java implementation and
`fixtures/` together, or it doesn't land ([Making a behaviour
change](#making-a-behaviour-change)). A wrapper change never changes a
verdict: wrappers read the clock, move bytes in and JSON out, pool
instances and map the outcome, and hold no parser, no crypto and no trust
decision. [PORTS.md](./PORTS.md) lists what each package runs on.

## Building the module

Every package except `java/` needs `aprv.wasm` (Node: the component,
`aprv.component.wasm`) before its tests can run. CI builds it once per run
in the `rust-wasm` job and hands it to every host job; locally you build it
the same way, on Linux x86_64:

```bash
eval "$(tools/wasm-toolchain.sh "$HOME/.cache/aprv-wasm-toolchain")"
rust/bindings/abi/build.sh "$OUT"
```

`tools/wasm-toolchain.sh` downloads and checks, by SHA-256, the pinned
wasi-sdk (34.0), wasm-tools (1.259.0), wit-bindgen (0.62.0) and the
OpenSSL 4.0.2 source, builds OpenSSL for `wasm32-wasip1`, and prints the
variables `build.sh` reads. The Rust compiler is the one
`rust/rust-toolchain.toml` pins (1.98.1, with the `wasm32-wasip1`
target); the released module's hash depends on it. `build.sh` writes
`aprv.wasm`, `aprv.component.wasm`, `aprv.wit` and `SHA256SUMS` into
`$OUT`, and fails when the module imports anything but `random-get`,
exports anything but the four operations and their helpers, or reads back
an interface that differs from `rust/bindings/abi/wit/aprv.wit`.
`rust/bindings/abi/README.md` has the details.

`tools/reproduce-wasm.sh <tag-or-ref> <sha256>` rebuilds the module of a
tag or commit in a fresh clone with that ref's own pins and compares the
hash; `--container` does the same inside a digest-pinned image. The
release job runs it once against its own artifact.

Then put the file where the package reads it. No package commits the
module on a branch; Go and Swift commit it once per release (the release
tooling does that, never a person):

| Package | Where the module goes | Or |
|---|---|---|
| Node | `node/wasm/aprv.component.wasm` | `APRV_COMPONENT` at build time |
| Go | `go/internal/wasm/aprv.wasm` | none: `//go:embed` needs the file |
| Python | `python/apple_purchase_receipt_verifier/aprv.wasm` | `APRV_WASM` for the tests and the build tools |
| Ruby | `ruby/lib/apple_purchase_receipt_verifier/aprv.wasm` | `APRV_WASM` for the tests |
| Swift | `swift/Sources/ApplePurchaseReceiptVerifier/Resources/aprv.wasm` | none: SwiftPM needs the resource |
| .NET | `dotnet/src/ApplePurchaseReceiptVerifier/wasm/aprv.wasm` | `APRV_WASM` at build time |
| Java `-wasm` | `java-wasm/src/main/wasm/aprv.wasm` | `-Daprv.wasm=PATH` |
| PHP, the Java server engine | an `aprv` binary built around the component (`rust/server/scripts/build-static.sh`) | `APRV_BIN` for PHP; `-Daprv.server.linux-x86_64=PATH` for Java |

Each package checks the file against the SHA-256 in the `.sha256` file
beside it, so a module other than the pinned one stops the build or the
first `Verifier`. After a core change, rewrite your local pins with
`tools/refresh-wasm-pins.sh "$OUT/aprv.wasm" "$OUT/aprv.component.wasm"`
and do not commit them: the release branch refreshes every pin at once.
The libraries themselves read no environment variable to find the module;
only their build and test tooling does.

## Running the tests

Each package runs all the cases of `fixtures/cases.json`, one named test
per case, and fails unless every case ran. From the repository root:

```bash
# Rust core (the workspace: core, OpenSSL adapter, surface, wire, ABI, C ABI)
cargo test --locked --workspace --manifest-path rust/Cargo.toml

# The C ABI's ctypes harness (rust/ffi/README.md, "Tests", has the C++ one)
cargo build --locked --manifest-path rust/ffi/Cargo.toml
python3 rust/ffi/tests/conformance.py rust/target/debug

# aprv-server, against a component
APRV_TEST_COMPONENT="$OUT/aprv.component.wasm" \
  cargo test --features compile --manifest-path rust/server/Cargo.toml

# The module alone, through a host that traps on any import but random-get
node tools/wasm-trap-host.mjs cases "$OUT/aprv.wasm" fixtures/cases.json

# Java, the independent implementation (Java 8 target, any modern JDK)
mvn -B -f java/pom.xml verify

# Java -wasm (Endive on Java 11+; the server-engine tests need the binary)
mvn -B -f java-wasm/pom.xml verify -Daprv.server.linux-x86_64="$APRV_BIN"

# Node (Node 20+): builds with jco and tsc, then the node:test suite
npm ci --ignore-scripts --prefix node && npm test --prefix node

# Go (1.25+)
go -C go test ./...

# Python (3.10+)
(cd python && uv run --locked --extra dev python -m unittest discover -s tests)

# Ruby (3.3+)
(cd ruby && bundle install && bundle exec rake test)

# Swift (6.3+; the manifest lives at the repository root)
swift test -c release -Xswiftc -enable-testing --force-resolved-versions

# .NET (SDK 8.0+)
dotnet test -c Release dotnet/tests/ApplePurchaseReceiptVerifier.Tests

# PHP (8.2+; the suite runs against a real aprv binary)
(cd php && composer install && APRV_BIN="$APRV_BIN" vendor/bin/phpunit)

# The shared cases file itself (ajv, from tools/package-lock.json)
npm ci --ignore-scripts --prefix tools && node tools/lint-cases.mjs

# No wrapper reaches a crypto, X.509, ASN.1, CMS or JWS API
node tools/check-one-implementation.mjs --enforce all
```

The last command is the one list of the APIs a wrapper must not touch
(CI's `one-implementation` job runs it); the packages' own suites do not
repeat it. Run it after any change under a wrapper's sources.

Each wrapper's README has its own section on the suite and its extra
legs (Node's runtimes and browsers, .NET's netstandard2.0 floor, Java's
Temurin 8 server-engine leg). Each package also carries a one-command
parity run over the corpora of generated receipts (1,179 rows and 5,000
mutants), which compares every answer byte for byte with the module's own
rows; PORTS.md names the script. The corpora are too large for the
repository: the nightly `corpus` job fetches the archive that
`fixtures/corpus.json` pins by URL and SHA-256.

### The three fixture tiers

Every suite verifies the same three shared fixture tiers:

1. `fixtures/generated/` and `fixtures/generated-0.7/`: deterministic
   fixtures (fake Apple PKI) written by the Java `FixtureGeneratorTest`
   and the `*Fixtures` generators beside it; the receipts in
   `generated-0.7/` carry the WWDR marker 0.7 checks. Regenerate only
   deliberately, then re-run **every** suite
   ([Generating a fixture](#generating-a-fixture)).
2. `fixtures/apple-official/`: Apple's own library test fixtures
   (vendored, MIT). Their test-CA-signed JWS mocks verify, their negative
   cases fail with our exact reason codes, and their genuine Xcode
   receipts/payloads are **rejected** against the real pinned Apple roots
   (anchor-pinning proof).
3. `fixtures/public-receipts/`: **genuine Apple-signed** sandbox and legacy
   receipts (vendored, MIT) that must verify against the real pinned Apple
   root, plus an Xcode receipt that must be rejected. This is the strongest
   tier: real Apple bytes.

The vectors those suites run the fixtures under are in `fixtures/cases.json`
([Conformance vectors](#conformance-vectors)). Inputs the shared fixtures
cannot express are built in code by the core's own tests (`rust/tests/`)
and by Java's throwaway test PKI (`java/src/test/.../TestPki.java`).

### Fuzzing

The parsers are the core's and OpenSSL's, so the fuzz targets that matter
reach them: `rust/fuzz/` holds five `cargo fuzz` targets over the core's
three operations, the receipt path and the C ABI, and a sixth,
`abi-call`, over the module's canonical ABI in Wasmtime
([`rust/fuzz/README.md`](./rust/fuzz/README.md)). `rust-fuzz` runs them
for a fixed budget on every change; the nightly `rust-fuzz-openssl` job
runs them over an OpenSSL built with AddressSanitizer and coverage
instrumentation, so libFuzzer follows edges inside OpenSSL's CMS, X.509
and ASN.1 code. `java-fuzz` fuzzes the Java implementation with Jazzer.
The wrappers' own fuzz jobs (`go-fuzz`, `python-fuzz`, `ruby-fuzz`,
`swift-fuzz`, `dotnet-fuzz`, `php-fuzz`) drive the public API through the
module, which exercises each wrapper's own boundary: lowering, lifting,
trap recovery. Every target is seeded from `fixtures/`, and the core's
targets carry the anchor-set invariant: an input one anchor set accepts
must fail against an unrelated one, which lets a fuzzer find a wrong
acceptance, not only a crash. A fuzz finding fails the job and opens no
public issue, since a crash in a parser can be a vulnerability
([SECURITY.md](./SECURITY.md)). Every fuzz job, nightly and per-push,
prints only the target and the input's hash and seals the rest to the
maintainer's key (`.github/scripts/fuzz-finding.sh`). If a fuzz job fails
on your pull request, the log names the target and nothing else: run that
target's `run.sh` locally (the `go-fuzz` targets with `go test -fuzz`) to
reproduce it, or ask the maintainer, who can open the sealed artifact. A
target that "failed without a crashing input" usually broke before it
fuzzed (a classpath, toolchain or build error), and that output is sealed
too, so run it locally first.

CI runs the suites on every supported runtime line
([SUPPORT-MATRIX.md](./SUPPORT-MATRIX.md)). The floors are claims we
test, not decoration: `@types/node` stays on 20, JUnit stays on 5.x and
`golang.org/x/sys` stays below v0.48 (Go 1.26) on purpose — see the
rationale comments in `.github/dependabot.yml` before "upgrading" them.

## Making a behaviour change

1. Write or change the case in `fixtures/cases.json` first
   ([Adding a case](#adding-a-case)): the case is what was decided.
2. Change the Rust core (`rust/src/`, or the OpenSSL adapter in
   `rust/openssl/`) and the Java implementation (`java/`) in the same pull
   request. The Java implementation is not a port of the core: it is the
   independent second opinion (docs/rust-core/DECISIONS.md R33), so fix it
   in its own code and idiom.
3. Run the core's suite, Java's suite and the module through the trap
   host. Every wrapper then answers the new case with no change of its
   own, because it runs the module; if a wrapper needs a change to pass a
   verdict case, the logic is in the wrong place.
4. A difference between the core and Java that you keep on purpose is
   recorded in docs/rust-core/DECISIONS.md R20 with its reason. One that
   changes an Apple-signed input's verdict, or accepts something
   unsigned, is a bug, never a divergence to record.

The nightly `java-differential` job (`tools/differential.sh`) runs the
core and the Java implementation over every input it collects and fails
on a difference R20 does not record.

## Adding a wrapper

A new language joins by running the same `aprv.wasm`, never by carrying
verification code. What a wrapper has to do is fixed by the WIT and by the
wire schemas, not by another wrapper's code:

1. **Bind the ABI.** `rust/bindings/abi/wit/aprv.wit` is the contract. A
   runtime with the Component Model binds it with its generator; any other
   calls the four core exports by hand, as the Go, Swift, Python, Ruby,
   .NET and Endive hosts do (`cabi_realloc`, the export, the return area,
   `cabi_post_*`; docs/rust-core/ARCHITECTURE.md §4 has the call, step by
   step). Supply `random-get` from the platform's CSPRNG and refuse any
   other import.
2. **Read the answers against the schemas.** The four JSON Schema 2020-12
   files in `rust/bindings/wire/schema/` describe `init`'s configuration
   and answer and the two verify results; the endpoint answer is Apple's
   JSON, passed through byte for byte.
3. **Hold the instance model** (ARCHITECTURE.md §5): one call at a time
   per instance, `init` once per instance with the `Config` roots, the
   clock read once per call and passed as `now-ms`, a trapped instance
   discarded, at most 3,145,729 bytes of any input copied into linear
   memory. Keep the six outcomes apart (ARCHITECTURE.md §4): a trap or an
   unreadable answer is `INTERNAL_ERROR`, never a verdict.
4. **Pin the module.** Check the packaged `aprv.wasm` against a
   `.sha256` file beside it before it is compiled, add that file to
   `tools/refresh-wasm-pins.sh`'s reach, and have the release job pack the
   file `build-wasm` built.
5. **Prove it.** A conformance runner that runs every case of
   `fixtures/cases.json` as one test and asserts every case id ran; the
   ABI tests (an `env` of 2, 255 and 2^32-1 traps, a verify before `init`
   and a second `init` trap, a wrong-length `random-get` traps, a trap in
   one instance leaves another verifying, 2,000 calls leave memory the same
   size); and a corpus runner whose rows match the module's reference rows
   byte for byte, wired into the nightly `corpus` job. Add the language to
   `tools/check-one-implementation.mjs`, a row to PORTS.md and to
   SUPPORT-MATRIX.md, and the package's CI needs to its own `CI-NOTES.md`.

A platform no Wasm runtime reaches uses `aprv-server` (HTTP or the
one-shot CLI) or the C ABI instead of a new wrapper.

## Adding or bumping a dependency by hand

`.github/dependabot.yml` holds every automated bump for seven days after the
release, the window in which a hijacked version usually gets pulled. A manual
`npm install`, `composer require` or gem bump skips that window. Check the
publish date before you commit the lockfile change:

```bash
npm view <package>@<version> time.modified
```

Under seven days old: wait, or say in the commit body why it cannot. CI
installs npm packages with `--ignore-scripts`; a dependency that needs its
install script to work is a reason to look for another dependency.

A bump of a toolchain the module depends on (the Rust compiler, wasi-sdk,
wasm-tools, wit-bindgen, OpenSSL) changes the module's bytes, and a bump
of a runtime a wrapper depends on (wazero, wasmtime-py, the `wasmtime` gem,
Wasmtime .NET, WasmKit, jco, Endive, the server's `wasmtime`) changes how
it runs. Either passes the full cross-host run before it merges
(docs/rust-core/DECISIONS.md R14).

Every ecosystem that has a lockfile commits it, and CI installs from it
strictly, so a bump reaches CI only as a committed change to a lockfile
(SECURITY.md, "Dependency policy"). Regenerate the file the package names
when you change a manifest:

| Package | Lockfile | Regenerate with |
|---|---|---|
| node | `node/package-lock.json` | `npm install` |
| rust | `rust/Cargo.lock` (the workspace: the core, the adapter, the bindings and the C ABI) | `CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile` in `rust/`; a plain `cargo update` ignores `rust-version` and can lock crates the declared floor cannot build |
| rust | `rust/server/Cargo.lock` (`aprv-server`, outside the workspace) | `cargo generate-lockfile` in `rust/server` |
| rust | `rust/bindings/abi/tests/Cargo.lock` (the Wasmtime ABI tests) | `cargo generate-lockfile` in `rust/bindings/abi/tests` |
| rust | `rust/fuzz/Cargo.lock` | `cargo generate-lockfile` in `rust/fuzz` |
| tools | `tools/package-lock.json` | `npm install` in `tools/` |
| python | `python/uv.lock` | `uv lock` |
| php | `php/composer.lock` | `composer update` (resolves at the 8.2 floor, see below) |
| ruby | `ruby/Gemfile.lock`, `ruby/gemfiles/*.lock` | `bundle lock` with the matching `BUNDLE_GEMFILE` |
| dotnet | `dotnet/**/packages.lock.json` | `dotnet restore --force-evaluate` under the newest SDK line `ci.yml` installs (10.0.x); an older band asks for a different implicit ILLink version and fails locked mode |
| swift | `Package.resolved`, `swift/bench/Package.resolved`, `swift/fuzz/Package.resolved` | `swift package update` |
| go | `go/go.sum`, `go/tools/go.sum` | `go get` then `go mod tidy` in the module's directory |

`php/composer.json` sets `config.platform.php` to 8.2.0, so a `composer
update` on any machine resolves the graph the PHP 8.2 leg has to install.
The Java builds pin exact versions in their poms and Maven has no lockfile
format.

## Conformance vectors

`fixtures/cases.json` is the normative contract between the Rust core and
the Java implementation, and every package answers it: one
language-neutral case per semantic fact, each naming a registered fixture,
the `Config` to build the verifier from, and either the payload fields the
call must return or the reason it must fail with. 399 cases today. Each
package reads the file through a thin adapter that knows nothing about
any individual case — `rust/tests/conformance.rs`,
`java/src/test/.../ConformanceCasesTest.java`,
`java-wasm/src/test/.../ConformanceCasesTest.java` (and
`ServerConformanceCasesTest.java` for the server engine),
`node/test/conformance.test.js`, `python/tests/test_conformance.py`,
`swift/Tests/.../ConformanceCasesTests.swift`, `go/conformance_test.go`,
`ruby/test/conformance_test.rb`, `php/tests/ConformanceCasesTest.php`,
`dotnet/tests/ApplePurchaseReceiptVerifier.Tests/Conformance070.cs`,
the C ABI's C++ and ctypes harnesses, `rust/server/scripts/cases.py` and
`tools/wasm-trap-host.mjs`.

**A behavior change means editing `cases.json` in the same commit.** The file
records what was decided, not what an implementation happened to do, so a
vector that disagrees with an implementation is a bug report against that
implementation until a human rules otherwise. Changing a returned field or a
failure reason without updating the vector leaves every suite disagreeing
with the contract.

The `comment` at the top of `cases.json` is the runner contract: how each
operation hands its input over, how `expected` is evaluated, and the rules
behind the expectations. Read it before adding a case.

### Adding a case

1. Register the fixture in the `fixtures` map if it is not there yet: `path`
   relative to `fixtures/`, `role` (`input`, `trust-anchor` or `support`),
   `codec` (`raw`, `base64`, `utf8` or `text`), and the file's `contentSha256` — the
   SHA-256 of the DECODED bytes, the ones the library is handed, not of the
   file as stored. That digest is enforced, not recorded: `lint-cases.mjs`
   re-hashes every registered fixture, and so does every adapter, over the
   whole registry before any case runs and again for each fixture a case
   loads. Regenerating or re-encoding a fixture without updating the digest
   fails every suite.
2. Append the case: a unique `id` shaped `<area>/<what-it-pins>`, a
   `description` of the fact it pins, the `operation` (`verifyReceipt`,
   `verifySignedData` or `verifyReceiptEndpoint`), `input.fixture` (or
   `input.requestBody` for a whole endpoint body), the `config`, and
   `expected`. A base64 spelling is a `decodeBase64` group instead; see
   "Adding a base64 spelling" below.
   A positive case carries `status: "ok"` plus the `fields` it pins, as JSON
   Pointers into the payload's JSON; a field it does not list is not pinned.
   A negative case carries `status: "error"` plus one of the eight reasons
   (never `INTERNAL_ERROR`), and a `fault` naming its single intentional
   defect. Where the outcome is implementation-defined,
   `expected: {"oneOf": [...]}` lists every outcome an implementation may
   give (at the endpoint, every `/status` the body may carry). Add a `clock` if — and only if — the answer depends on the
   current time; see below.
3. Run `node tools/lint-cases.mjs` (after
   `npm ci --ignore-scripts --prefix tools`, which installs the ajv it
   validates with). It validates the file against
   `fixtures/cases.schema.json`, re-hashes every registered fixture, and
   fails on a fixture file no case registers or an `input` fixture no case
   uses. CI runs the same command in the `conformance` job.
4. Run the core's and Java's suites, and the module through the trap
   host. The case must pass in both implementations; a disagreement is the
   finding, not something to paper over in an adapter. Every runner also
   checks that each case id in the file ran, so a case an adapter silently
   skips fails the suite. Only an explicit test filter turns that check
   off.

### Adding a base64 spelling

The `receipt-data` and `x5c` base64 spellings live in `cases.json` as
`decodeBase64` groups, one list for every package. Do not add a spelling
list to a package's own tests. Put the string in the group for its category
(`base64/reject-whitespace-inside`, `base64/decodes-to-41`, ...) or start a
new group:

- `input.texts` holds the exact strings; the empty string and control
  characters are allowed. A string appears in one group only.
- An accepting group has `expected: {"status": "ok", "bytesHex": "<hex>"}`,
  the bytes every text decodes to. A refusing group has
  `expected: {"status": "error", "reason": "MALFORMED"}`.
- `decoders` names the decoders the group runs through, normally
  `["receipt-data", "x5c"]`. The Rust core and Java call their decoders
  directly. A wrapper has no decoder of its own, so its runner passes a
  `receipt-data` text through `verifyReceipt` and an `x5c` text through a
  JWS that carries it, and checks which side of the rule the text lands
  on. A refusal is `MALFORMED` from the receipt-data decoder and
  `INVALID_CERTIFICATE` from the x5c decoder; the runner maps the reason,
  so a case never repeats it.
- The `description` says why, citing the Apple measurement in
  `docs/evidence/2026-09-23-verifyreceipt-base64.md` where there is one.

`lint-cases.mjs` checks each spelling against the rule on its own and
refuses a string listed twice. When a text fails, the runner names the case
id, the index and the escaped text.

Field paths in `expected.fields` are JSON Pointers (RFC 6901) into the
payload as JSON: `ReceiptPayload.toJson()` for a receipt, the signed JSON
for a JWS, Apple's response body for the endpoint. One extension, a token
written `[key=value]`, selects the single array element whose member `key`
equals `value`; `expected.lengths` pins an array's length; `null` means
"absent or JSON null". The `comment` at the top of `cases.json` carries the
full grammar.

### Generating a fixture

Fixtures under `fixtures/generated/` and `fixtures/generated-0.7/` are
signed by a fake Apple PKI built in `java/src/test/.../TestPki.java`, so no
real Apple key material is needed. The receipts under `generated-0.7/` were
re-minted with the WWDR marker on their intermediate, which 0.7 checks; the
`comment` in `cases.json` lists every generator that writes there and the
order to run them in. The original twelve generators write the 0.6 set, all
at fixed epoch instants so nothing depends on generation time:

- `FixtureGeneratorTest` — the original set. Gated behind
  `mvn test -Dtest=FixtureGeneratorTest -Dfixtures.generate=true`.
- `PortDivergenceFixtures` — the receipt whose attribute type is above
  2^31-1, and the receipts and payloads carrying no date of their own.
- `HostileReceiptFixtures` — the four defective-signer receipts, the
  receipt-path twins of the `x5c` certificate mutations
  `HostileJwsFixtures` builds.
- `HostileJwsFixtures` — the eight hostile-JWS fixtures Python's
  coverage-guided fuzzing found escaping the library as bare exceptions,
  plus the `x5c[2]` vector that closed the last parser differential.
- `JwsSegmentFixtures` — the six empty-or-non-object compact-JWS segment
  fixtures (RFC 7515 §7.1 requires the first two segments to decode to JSON
  objects).
- `LargeReceiptFixture` — the two receipts pinning the contract's
  normative resource floor: 1,048,576 bytes of DER and 20,000 ASN.1 nodes
  in a single parse.
- `AbsentSignerFixture` — the receipt that separates "the signer is not in
  the bag" from "something in the bag is not a certificate".
- `ReceiptIdsFixture` — the receipt carrying the four attributes that used
  to sit in `unknownAttributes`: app-level 1, 15 and 16, and in-app 1713.
- `ReceiptCmsDefectFixtures` — the four receipts whose single defect sits in
  the CMS structure rather than in a certificate or in the payload: a
  receipt-signing end entity standing where the intermediate belongs, the
  intermediate absent from the certificate bag, a SignerInfo signature of
  zero bytes, and a CMS signed over zero bytes of encapsulated content.
- `X5cBase64Fixtures` — the five transactions whose `x5c[0]` is the
  genuine leaf spelled as something other than canonical standard base64
  (RFC 7515 §4.1.6): a junk character inside it, the base64url alphabet,
  PEM-style line breaks, the `=` padding omitted, and one `=` too many.
- `VerificationOrderFixtures` — the seven receipts that pin the legacy
  verification order: a creation date that is unreadable or stated twice,
  and a top-level entry or in-app purchase that cannot be read, each under
  a trusted, a foreign or an expired chain as the vector needs, with their
  own trusted and expired roots.
- `ReceiptBase64CapFixture` — the receipt string at the base64 receipt cap:
  the canonical base64 of a genuinely signed receipt of 2,359,296 bytes,
  which is exactly 3,145,728 characters. It writes the string and its root
  to `fixtures/generated-0.7/receipt-b64-at-cap.txt` and
  `receipt-b64-cap-root.der`, the pair the cases read, and the same string
  to `fixtures/limits/receipt-b64-at-cap.txt`, from which
  `node tools/generate-limit-fixtures.mjs` builds the over-cap twin, so
  that script runs after it. Until the next regeneration the committed
  `limits/` copy is still the 0.6 string, whose root is gone; its readers
  (the `aprv-server` size tests, the length check in
  `generate-limit-fixtures.mjs` and the replay in
  `docs/evidence/2026-09-26-openssl-asn1-payload/`) use only its length.

The last eleven run as a `main`, not a `@Test`, so none of them costs the
suite a permanently skipped test. All eleven regenerate the same way; only
the class name and the output directory change:

```bash
mvn -B -q -f java/pom.xml test-compile
mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile=/tmp/cp.txt
java -cp "java/target/test-classes:java/target/classes:$(cat /tmp/cp.txt)" \
     io.github.emindeniz99.applepurchasereceiptverifier.<ClassName> \
     <output>
node tools/lint-cases.mjs   # re-hash: every contentSha256 must be updated
```

`<output>` is `fixtures/generated` for the other nine,
`fixtures/generated-0.7` for `LargeReceiptFixture` and `fixtures` for
`ReceiptBase64CapFixture`; with no argument each writes to that same
default. Never point those two at `fixtures/generated`: their outputs
run to 1 MB and 3 MB, and only the copies in `generated-0.7/` and
`limits/` are exempt from the 100 KB rule.

Every run mints fresh keys, so regenerating changes every byte and every
`contentSha256` that records it. The signing keys are deliberately not kept:
a fixture cannot be re-signed under a root that is already published, which
is why each generator emits its own roots beside its inputs.

### The clock

A case may carry `clock: {"now": "<ISO-8601 UTC instant>"}`, and the runner
builds its `Config` with a clock fixed at that instant; without one the
default clock runs. Each package's `Config` takes a clock in its own idiom
(`java.time.Clock`, a `() => number`, a callable, a closure, a PSR-20
`ClockInterface`, a `Func<long>`), so no runner fakes time and no runner
skips a case for want of a seam. A wrapper reads that clock once per call
and passes the value to the module as `now-ms`.

The clock matters in two places: the certificate-validity instant when the
input states no usable date (a receipt whose first attribute 12 is missing
or does not parse, a JWS whose `signedDate` is missing or not a
representable instant), and `request_date` at the endpoint. Pin a clock on
any case whose verdict or asserted fields could move with it: the dateless
and unreadable-date cases pin 2025-01-01 unless the case is about the clock
itself, and two endpoint cases pin that the clock does move the verdict of
a dateless receipt. A payload that states its own date is judged at that
date, so the expired-chain cases need no clock. How old a signed payload
may be is the caller's decision, so no case pins one.

## Spikes and evidence

Every experiment's code goes into the repo, even code that answered "no":
a note at `docs/evidence/<date>-<name>.md` and its sources in
`docs/evidence/<date>-<name>/`, committed together. See
[docs/evidence/README.md](docs/evidence/README.md) for the layout, and
what stays out: binaries (`aprv.wasm` included), local paths, secrets and
production receipts.

## Commits

Conventional Commits with a **mandatory scope**:

```
<type>(<scope>): <imperative subject, lowercase, ≤72 chars total>
```

- Types: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `chore`, `build`, `ci`, `revert`.
- Scopes are areas: `java`, `node`, `python`, `swift`, `go`, `ruby`, `rust`,
  `php`, `dotnet`, `jvm-interop`, `fixtures`, `certs`, `ci`, `release`,
  `docs`, `repo`.
- Body explains *why* (constraint, incident, trade-off), not what the diff
  already shows. Wrap at 72 chars.
- `feat`/`fix` drive release-please's version bump — use them only for
  user-visible changes.
- No binary over 100 KB. The exceptions are the two committed copies of
  `aprv.wasm` (Go and Swift), written by the release tooling and never by
  a contributor, and the size-limit fixtures under `fixtures/limits/` and
  `fixtures/generated-0.7/`, written by `tools/generate-limit-fixtures.mjs`
  and the Java generators `ReceiptBase64CapFixture`,
  `LargeReceiptFixture` and `VerifierApiFixtures`.

## Merging

Pull requests merge with a **real merge commit** — never squash, never
rebase-merge. Per-commit history is the record of how the work was built;
squashing erases it irreversibly. (Squash and rebase merges are disabled in
the repo settings.)

Give the merge commit a body of the form `Merges #57: <PR title without its
type(scope) prefix>`, not GitHub's default, the bare PR title, which is a
Conventional Commit line. release-please reads merge commit bodies as commits
too, so a conventional body there duplicates the entry the branch commit
already produces (0.4.0's changelog lists `deps: Bump actions/setup-go from
6.5.0 to 7.0.0` twice for exactly this reason). Dropping only the prefix
keeps `git log` readable; the type, scope and any breaking marker still live
on the branch commit, which release-please does read.

## Releases

Fully automated — do not publish from a laptop:

1. Conventional Commits on `main` → release-please opens/updates a release PR
   (one version for every package; extra-files bump every manifest and
   version constant that carries a version string, and a step in the same
   workflow regenerates the lockfiles that carry it too). On that branch,
   `release-please.yml` also builds the module and the Linux server
   binaries, rewrites every committed copy and pin of `aprv.wasm`
   (`tools/refresh-wasm-pins.sh`), and writes the Linux server binaries'
   `sha256sum` lines into `php/SHA256SUMS`, in one commit.
2. Merging that PR creates the tag + GitHub Release, and the workflow
   dispatches `release.yml` at the tag.
3. `release.yml` builds `aprv.wasm` and the component once, with no cache
   (`build-wasm`), and the `aprv-server` binaries per platform
   (`build-server`); attests each with SLSA build provenance and a
   CycloneDX SBOM; attaches the module, the component, the WIT, the
   binaries and `SHA256SUMS` to the Release; and pushes the server image
   to GHCR (and Docker Hub once bootstrapped). The publish jobs take those
   files and never rebuild them: npm (OIDC), PyPI (OIDC), RubyGems (OIDC),
   NuGet (OIDC), Maven Central (token + GPG; the main artifact, and the
   `-wasm` artifact with its two classifier jars once the owner sets
   `APRV_PUBLISH_JAVA_WASM`, BOOTSTRAP.md), and the `go/vX.Y.Z` tag that
   publishes the Go module
   through `proxy.golang.org`. SwiftPM consumes the plain tag directly,
   and Packagist reads the tag once the owner has submitted the repository.
   crates.io stays at 0.7 until `openssl-sys` accepts OpenSSL 4
   (BOOTSTRAP.md).

Every publish job is version-gated: it skips loudly if the registry already
has that version, so re-runs are safe, and each one proves the built artifact
carries the library before pushing it. **Never rename `release.yml`** — npm,
PyPI, RubyGems, crates.io and NuGet trusted publishing all match the workflow
filename.

Registries that are not live yet each need a one-time owner action, listed
per registry in [BOOTSTRAP.md](./BOOTSTRAP.md).

Maven Central's Usage Center caps `io.github.emindeniz99` at 7 releases and
about 80 MB per calendar month, and every release-please PR merge spends
one, since `release.yml` publishes to Central on every tag. Once the
`-wasm` artifact ships, with its two server classifier jars, a release is
about 10.5 MB, so the working budget is 5 releases a month. Merge a
release PR only for a consumer-visible
change — a fix, a feature, a docs correction that registries display, or a
security bump of a shipped dependency (an OpenSSL advisory that reaches
the core is one) — not for a `Package.resolved`/lockfile or CI-only bump;
let release-please accumulate those into the next real release instead.
Before merging, check the month's count on https://central.sonatype.com
(Usage Center) or `git tag --sort=-creatordate | head`, and keep at least
2 releases in reserve for an emergency fix. Note that SwiftPM consumers
never see `Package.resolved` — they resolve from `Package.swift`'s `from:`
floors — so a `Package.resolved` bump alone changes nothing for them.
