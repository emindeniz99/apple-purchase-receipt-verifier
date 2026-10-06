# Apple's verifyReceipt and a receipt with two SignerInfos

| File | What it answered |
|---|---|
| `splice.py` | Writes the variants: every byte of the genuine receipt kept, only the signerInfos SET (and the length headers around it) changed, plus controls |
| `send.sh` | Posts each variant to a verifyReceipt URL and prints Apple's `status` only |
| `OurVerdicts.java` | The Java implementation's answer for each variant |
| `core/` | The Rust core's answer for each variant, through the Go package and its pinned `aprv.wasm` |
| `MakeVariants.java` | The first attempt, which rebuilt the envelope with BouncyCastle; Apple refused even its one-genuine-SignerInfo control, because BouncyCastle sorts the certificates SET (`results/apple-bouncycastle-reencoded.txt`) |
| `results/apple.txt` | Apple's statuses, both receipts, both endpoints, two runs |
| `results/java.txt`, `results/core.txt` | Our two implementations on the same variants |

Reproduce, with `$REPO` the repository root and `$SCRATCH` any directory outside it:

```sh
for r in receipt-sandbox-g5 receipt-sandbox-legacy; do
  python3 -I splice.py "$REPO/fixtures/public-receipts/$r.b64" "$SCRATCH/$r"
  for u in sandbox buy; do sh send.sh "$SCRATCH/$r" "https://$u.itunes.apple.com/verifyReceipt"; done
  (cd core && go run . "$SCRATCH/$r")
done
# Java: mvn -f "$REPO/java/pom.xml" -q compile, then javac/java OurVerdicts.java with
# java/target/classes, bcprov/bcutil/bcpkix 1.86 and jackson-core 2.22 on the classpath.
```
