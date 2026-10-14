# Reproduce the Java legacy receipt review

These sources are review experiments, excluded from the shipped library.
They print verdicts, counts and allocation figures. They do not print receipt
fields, purchase identifiers or signing timestamps.

| Source | Question |
|---|---|
| `LegacyReviewProbe.java` | Do the real Apple sandbox chains verify on Temurin 17, including after root expiry? What does the unsigned-attribute cap refuse? Can creation-date reading avoid attribute maps? |
| `SecurityReviewProbe.java` | Can payload/signature substitutions or malformed RSA encodings verify? What does a real 1,000-way BC OID hash collision cost inside an unsigned CMS attribute table? |
| `run.py` | Compile and replay the experiments with the Maven build's actual dependencies, keeping generated inputs and results outside the repository. |
| `../2026-10-05-java-presignature-parse-cost/PresignatureCost.java` | Existing generator and allocation benchmark for cap-sized synthetic receipts; reused without modification. |

Build the Java artifact using Temurin 17, then run the experiment. `REPO`
is the repository root, `SCRATCH` a directory outside it, and `JAVA_HOME`
the Temurin 17 installation. Maven needs the environment's normal network
proxy and CA trust if its dependencies are not already cached.

```sh
mvn -f "$REPO/java/pom.xml" -B clean verify
python3 "$REPO/docs/evidence/2026-10-14-java-legacy-temurin17-review/run.py" \
  --repo "$REPO" --jdk "$JAVA_HOME" --scratch "$SCRATCH"
```

The script reads the classpath from a Surefire XML report. It does not assume
the repository's dependency versions and writes its measurements to
`$SCRATCH/results.txt`. Timing figures depend on the machine, JIT and GC;
allocation is cumulative per call, not peak live heap. The alternate date
reader is an experiment, not a proposed change to the production decoder.

To run only the deeper security experiments, add `--security-only` to the
Python command. It runs 1,119 binding and RSA encoding assertions, then
compares ordinary and colliding unsigned OIDs at 250, 500 and 1,000 entries.
The RSA cases use a synthetic pinned PKI and deliberately malformed encoded
messages, with both SHA-1 and SHA-256. Their valid controls must verify.
The OID experiment uses a public Apple sandbox receipt without changing its
signed content or signature. It asserts the distinct OIDs have identical BC
hash codes and that the full base64 stays under the library's size cap.
Generated receipt files stay under the scratch directory.
