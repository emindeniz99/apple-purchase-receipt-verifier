# Endive build-time compiler (2026-09-26)

Sources for `../2026-09-26-endive-build-time-jvm.md`. The question: can
the current Route C `aprv.wasm` (Rust core + OpenSSL 4.0.2, CMS path,
template payload reader; round 4's `new-c.wasm`) go through Endive's
build-time compiler into JVM bytecode, ship as an ordinary Maven library,
and verify receipts and JWS in a separate clean Maven project, with the same
answers as the reference and no native verifier code in the JVM?

Nothing here is production code. The library, the trap probe and the
consumer are throwaway Maven projects. The scripts copy each one to
`$SCRATCH/endive/work/` and build it there, so no `target/` directory lands
in this folder. The `.wasm` files are inputs passed on the command line,
not files kept here.

Placeholders:

| Name | Meaning |
|---|---|
| `$REPO` | the repository root |
| `$SCRATCH` | the wasm bake-off's scratch directory; this round writes under `$SCRATCH/endive` |
| `$CORPORA` | the substrate bake-off's request corpora (1,179 rows, plus 5,000 mutants in `fuzz.jsonl`) |
| `$JDK11`, `$JDK17`, `$JDK21`, `$JDK25`, `$JDK8` | JDK or JRE homes (see `results/versions.txt`) |
| `$A4` | `../2026-09-26-openssl-asn1-payload` (round 4, which builds the `.wasm`) |
| `$PREV` | `../2026-09-26-wasm-architecture-bakeoff` (the Node runner, `js/run.mjs`) |
| `$SPIKE` | `../2026-09-26-security-substrate-bakeoff` (`py/same.py`, `py/tri.py`) |

## Files

| File | What it is for |
|---|---|
| `lib/pom.xml` | The library `spike.aprv:aprv-endive`: the `endive-compiler-maven-plugin` 1.1.0 `compile` goal on `aprv.wasm` (`interpreterFallback` FAIL, `NameSectionMethodPrefixer`), and one runtime dependency, `run.endive:runtime` |
| `lib/src/main/java/spike/aprv/endive/AprvWasm.java` | The one hand-written library class. It supplies the module's two imports (`aprv.clock_now_ms` from the system clock, `aprv.random_get` from `SecureRandom`), instantiates the generated module, and moves bytes in and out of guest memory |
| `trap/` | `trap-probe`: a six-function WAT module (out-of-bounds load, store and fill, `unreachable`, divide by zero, unbounded recursion), compiled by the same plugin |
| `consumer/pom.xml` | The clean consumer. It depends on `aprv-endive` (and `trap-probe`) from a Maven repository, and has no plugin or toolchain configuration |
| `consumer/src/main/java/spike/consumer/Driver.java` | A port of the bake-off's `js/driver.mjs`: corpus rows through the unchanged C ABI, the same row format |
| `consumer/src/main/java/spike/consumer/Main.java` | Modes: `corpus`, `bench`, `threads`, `shared`, `memory`, `maps`, `trap`, `instances` |
| `consumer/src/main/java/spike/consumer/Json.java` | A minimal JSON reader and writer, so the consumer needs no JSON library |
| `scripts/env.sh` | Shared settings: where the `.wasm` and the reference rows are |
| `scripts/build.sh` | `lib`, `trap`, `consumer`. The first two deploy to a file-based repository (`$SCRATCH/endive/remote-repo`); the consumer builds from it with an empty local repository |
| `scripts/run.sh` | `parity` (corpus rows, compared three ways) and `java` (any consumer mode) on one JDK |
| `scripts/java.sh` | Three-way Java tallies (`$SPIKE/py/tri.py`) for every Endive run |
| `scripts/inspect.sh` | `jar` (contents, the `.meta` module, generated classes, dependencies), `methods` (bytecode size per generated method), `native` (native libraries, native and FFM calls, mapped shared objects, loaded classes) |
| `scripts/bench.sh` | `jvm`, `node`, `instances`, `build` (compile-goal time), `jfr` (profile) |
| `scripts/facts.sh` | Endive's versions, POM dependencies and quoted documentation lines, from Maven Central and endive.run |
| `py/exact.py` | Byte-for-byte row comparison, with the endpoint's `request_date*` masked |
| `py/jfr_top.py` | JFR samples aggregated by innermost frame and by compiled Wasm function |
| `py/method_sizes.py` | Generated method sizes against the JVM's 64 KiB and 8,000-byte (JIT) limits |
| `results/endive-facts.txt` | Task: what Endive is (coordinates, versions, POMs, documentation quotes) |
| `results/parity.txt` | Every corpus run: JDK 11, 17, 21 and 25, and 25 with `ByteArrayMemory` |
| `results/java-tallies.txt` | Java tallies per run |
| `results/jar-inspection.txt` | What the jar holds and what the consumer resolves |
| `results/method-sizes.txt` | Generated method sizes |
| `results/native-check.txt` | Native-code evidence on JDK 17, 21 and 25 |
| `results/java-floor.txt` | JDK 8 refusal, class-file versions, JDK 11 trap run |
| `results/trap.txt` | The trap probe on JDK 17, 21 and 25 |
| `results/concurrency.txt` | Two instances, one instance per thread, and one shared instance |
| `results/bench.txt`, `results/build-time.txt`, `results/profile-jws.txt` | Performance, compile-goal time, JFR profile |
| `results/versions.txt` | Exact versions |

## Reproduce

These commands assume Linux x86_64 with Maven 3.9, Node 22, and round 4's
Route C template build at `$SCRATCH/asn1/art/new-c.wasm` (round 4's
`scripts/build.sh routec-new`). They also need round 4's reference rows in
`$SCRATCH/asn1/run` and `$SCRATCH/asn1/wrun`, from its `parity.sh` runs.
The build side's local Maven repository (`$SCRATCH/endive/m2-build`) can
start empty.

```sh
export REPO=... SCRATCH=... CORPORA=... JDK8=... JDK11=... JDK17=... JDK21=... JDK25=...
EP=$REPO/docs/evidence/2026-09-26-endive-build-time-jvm
$EP/scripts/facts.sh > $EP/results/endive-facts.txt
# build machine: wasm -> Endive -> jar -> file repository; then the clean consumer
$EP/scripts/build.sh lib && $EP/scripts/build.sh trap && $EP/scripts/build.sh consumer
# correctness: 1,179 rows + 5,000 mutants per JDK
rm -f $EP/results/parity.txt
for v in 11 17 21 25; do $EP/scripts/run.sh parity $v cases hostile algorithms substrate fuzz; done
JOPTS=-Dspike.aprv.memory=bytearray TAG=jdk25-bytearray $EP/scripts/run.sh parity 25 cases hostile algorithms substrate fuzz
$EP/scripts/java.sh > $EP/results/java-tallies.txt
# what was built and what runs
$EP/scripts/inspect.sh jar > $EP/results/jar-inspection.txt
$EP/scripts/inspect.sh methods > $EP/results/method-sizes.txt
$EP/scripts/inspect.sh native > $EP/results/native-check.txt
# Java floor, traps, concurrency
{ echo "## JDK 8"; $EP/scripts/run.sh java 8 corpus $CORPORA/algorithms.jsonl 2>&1 | head -3; } > $EP/results/java-floor.txt
for v in 17 21 25; do echo "## JDK $v"; $EP/scripts/run.sh java $v trap; done > $EP/results/trap.txt
$EP/scripts/run.sh java 21 memory
for v in 17 21 25; do $EP/scripts/run.sh java $v threads $CORPORA/cases.jsonl 4 3; done
$EP/scripts/run.sh java 21 threads $CORPORA/hostile.jsonl 4 2
timeout 600 $EP/scripts/run.sh java 21 shared $CORPORA/cases.jsonl 4 1   # hangs: kill the JVM afterwards
# performance
$EP/scripts/bench.sh build > $EP/results/build-time.txt
{ $EP/scripts/bench.sh jvm; $EP/scripts/bench.sh node; $EP/scripts/bench.sh instances; } > $EP/results/bench.txt
$EP/scripts/bench.sh jfr > $EP/results/profile-jws.txt
```

`results/java-floor.txt` also holds hand-run lines: the class-file version
count per jar, and the JDK 11 trap run. `results/concurrency.txt` holds the
outputs of the concurrency commands above, with the notes and the `jstack`
excerpt of the shared-instance hang. The command for each part is written
next to it in the file.

## What is not here

This folder has no binaries: no `.wasm`, `.jar`, `.class`, `.jfr` or local
Maven repositories. It also has no downloaded sources (the Endive sources
jar and `llms-full.txt` were read in `$SCRATCH/endive` only) and no
receipts. Every input row comes from `$CORPORA`, which is built from
`fixtures/` and generated test keys.
