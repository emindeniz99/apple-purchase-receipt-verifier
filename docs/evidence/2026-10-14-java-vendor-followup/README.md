# Java vendor follow-up probes

Question: does the standalone Java implementation preserve trust while
accepting ordinary algorithm and chain changes its provider already supports?

| File | Question answered |
|---|---|
| `VendorProbe.java` | Do independently valid ES384 and changed-chain JWS verify? Do equivalent CMS changes verify? Do foreign roots, changed signed bytes, ECDSA boundary values, and larger invalid JWS fail closed? |
| `run.sh` | Can the unchanged Java suite and the probes be reproduced on Temurin 17 with every build output outside the repository? |

The companion [note](../2026-10-14-java-vendor-followup.md) records the
review, versions, results and limitations. These sources are disposable
evidence; they are not built by CI or included in the library.

## Reproduce

Start with main commit `0b8766f02b473c4e312da24a18b678ea3bea0267`
or this evidence branch. Set `REPO` to the repository root, `SCRATCH` to a
fresh directory outside it, and `JAVA_HOME` to Temurin 17. Put Maven
3.9.16 on `PATH`.

```sh
export REPO SCRATCH JAVA_HOME
bash "$REPO/docs/evidence/2026-10-14-java-vendor-followup/run.sh"
```

The script copies tracked `java/`, `fixtures/` and `certs/` files into
`$SCRATCH/tree` and runs exactly `mvn -B -f java/pom.xml verify` there.
It then resolves the classpath, compiles the probe with `javac --release 8`,
and runs it with a 512 MiB heap. The Maven repository, classes and logs
are all under `$SCRATCH`. It uses `HTTPS_PROXY` when present, and the
executor's Java CA store when available. It introduces no library setting.

After that build, rerun only the probe with:

```sh
bash "$REPO/docs/evidence/2026-10-14-java-vendor-followup/run.sh" --probe-only
```

Results are `$SCRATCH/runtime.log`, `$SCRATCH/verify.log` and
`$SCRATCH/probe.log`. The probe prints labels, reasons, counts, sizes and
durations only. It generates fresh EC keys in memory and reads only the
two public sandbox receipt fixtures; it prints no payload, identifier,
certificate, private key or receipt date. Assertion failures name the
probe, never the input. The timing loop is a smoke measurement, not JMH.

Runtime downloads used for this run (keep them under `$SCRATCH`):

- Temurin 17 HotSpot: <https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse>, which resolved to 17.0.20.1+1 for this review. Pin that release when reproducing these numbers; the `latest` endpoint changes.
- Maven 3.9.16: <https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.16/apache-maven-3.9.16-bin.tar.gz>.
- BouncyCastle, Jackson, JSpecify and JUnit are resolved from Maven Central at the versions in the unchanged `java/pom.xml`.

No downloaded source, binary, generated receipt, key or raw build log is
committed in this folder.
