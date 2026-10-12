# Source-scan regex vs the hand-written loop

| File | Question it answered |
|---|---|
| `Compare.java` | Does one regex strip comments from every Java source under `java/src` exactly as the 50-line character loop in `TrustStoreIsolationTest` did, on the real sources, on the edge cases, and on a 200,000-character literal? |

Reproduce:

```bash
mkdir -p $SCRATCH/strip
javac -d $SCRATCH/strip $REPO/docs/evidence/2026-10-12-java-source-scan-regex/Compare.java
java -cp $SCRATCH/strip Compare $REPO/java/src
```

Expected: `88 files, 0 differ`, five `same` lines, `big literal + comment: true`.
