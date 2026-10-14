# Java vendor review probes

Question: does the standalone Java implementation enforce origin with bounded
work while accepting supported future signing and certificate shapes?

| File | Question answered |
|---|---|
| `VendorReviewProbe.java` | Do independent BC signature/PKIX controls pass when the library refuses another JWS algorithm, another chain shape, or an equivalent issuer-name encoding? Do JWS mutations, foreign roots, wrong purposes and colliding JSON names escape rejection? |
| `run.py` | Can the complete suite and the extra probes be reproduced on a selected JDK without putting outputs into the source checkout? |

The result and review are in
[the dated note](../2026-10-14-java-vendor-review.md).
This is review code, outside the Maven source roots; CI builds none of it.

## Reproduce

Use Python 3.9+, Maven 3.9.16 and Eclipse Temurin 17.0.20.1+1 (HotSpot),
Linux x86-64. Set `REPO` to the repository root, `SCRATCH` to a directory
outside it, `REVIEW_JDK` to the unpacked JDK, and `REVIEW_MAVEN` to Maven's
executable. Run from any directory:

```sh
python3 "$REPO/docs/evidence/2026-10-14-java-vendor-review/run.py" \
  --repo "$REPO" --scratch "$SCRATCH" \
  --jdk "$REVIEW_JDK" --maven "$REVIEW_MAVEN"
```

The script copies `java/`, `fixtures/` and `certs/` into
`$SCRATCH/checkout/` and runs `mvn -B -f java/pom.xml verify` there, without
changing any source or POM. Maven's local dependency cache also goes to
`$SCRATCH`. `--build-only` runs the suite without the probes;
`--probe-only` reuses the scratch build and compiles/runs just the probes.
Choose an empty scratch directory for a fresh review.

The script respects `MAVEN_OPTS`. When `HTTPS_PROXY` or `HTTP_PROXY` is set
to an unauthenticated proxy, it writes a Maven proxy settings file under
`$SCRATCH`. On the managed environment used for the review, Maven also
needed the environment's Java CA store:

```sh
export MAVEN_OPTS='-Djavax.net.ssl.trustStore=/etc/ssl/certs/java/cacerts'
```

Tool downloads used in this run:

- [Temurin 17.0.20.1+1](https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.20.1%2B1/OpenJDK17U-jdk_x64_linux_hotspot_17.0.20.1_1.tar.gz).
- [Maven 3.9.16](https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.16/apache-maven-3.9.16-bin.tar.gz).
- For the static dependency read only: BC 1.86
  [bcprov sources](https://repo.maven.apache.org/maven2/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86-sources.jar)
  and [bcpkix sources](https://repo.maven.apache.org/maven2/org/bouncycastle/bcpkix-jdk18on/1.86/bcpkix-jdk18on-1.86-sources.jar).

Outputs: `java-version.log`, `maven-version.log`, `verify.log`,
`suite-summary.json`, `probe-compile.log`, `probe.log`, and the scratch
checkout's Surefire XML reports. Compiled classes, jars, dependency sources,
downloads and raw logs stay outside the repository.

The probes create fresh keys in memory, pin only their own root for positive
synthetic controls, and separately require the default Apple roots to refuse
the synthetic input. They read only the two public sandbox receipt fixtures.
They print no payloads, certificate names, identifiers or signing instants.
Timing uses 20 warm-up calls and 20 measured calls per JSON shape on one
thread with a 512 MiB heap; it is not JMH. Hash-table seeding, JIT state and
runner load can change the timings and collision-overflow point.
