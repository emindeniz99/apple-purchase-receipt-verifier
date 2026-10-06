# Walkthrough trace: code

| File | Question it answered |
|---|---|
| `Trace.java` | What does each step of `ReceiptCore.verifySignature` see on a genuine receipt, and does the chain still pass at the clock? It calls the library's own classes, the private `ReceiptCore` methods by reflection, and prints one line per step. |

`Trace` declares the library's package, so it is compiled together with
`java/src/main/java` and `java/src/shared/java`, not against the jar.

## Reproduce

From the repository root (`$REPO`), with every output in `$SCRATCH`:

```sh
mvn -B -q -f java/pom.xml dependency:build-classpath -Dmdep.outputFile="$SCRATCH/cp.txt"
CP="$(cat "$SCRATCH/cp.txt")"
javac -nowarn -d "$SCRATCH/classes" -cp "$CP" \
    $(find java/src/main/java java/src/shared/java -name '*.java') \
    docs/evidence/2026-10-06-walkthrough-trace/Trace.java
for r in receipt-sandbox-g5 receipt-sandbox-legacy; do
  java -cp "$SCRATCH/classes:$CP" \
      io.github.emindeniz99.applepurchasereceiptverifier.Trace \
      "fixtures/public-receipts/$r.b64"
done
```

Each output line starts with the step number of java/WALKTHROUGH.md §6.3.
The clock line, and the instant in the "same chain at the clock" message,
change with the day the trace runs.
