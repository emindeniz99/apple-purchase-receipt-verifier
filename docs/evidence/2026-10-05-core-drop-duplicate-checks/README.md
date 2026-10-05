# Duplicate checks in the core: probes

| File | Question |
|---|---|
| `Probe.java` | Does BouncyCastle 1.86 parse a constructed `OCTET STRING` whose chunk is a `UTF8String`, the shape of an eContent re-chunked with a foreign tag? |
| `without-content-type-match.patch` | Does OpenSSL refuse a signed `contentType` attribute that differs from the eContentType on the core's path, once the core's own comparison is gone? |

Reproduce the BouncyCastle probe (any JDK 8 or later; the jar is
`org.bouncycastle:bcprov-jdk18on:1.86` from Maven Central,
<https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.86/>):

```sh
mkdir -p "$SCRATCH/bcprobe"
curl -sSfo "$SCRATCH/bcprobe/bcprov.jar" \
  https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar
javac -d "$SCRATCH/bcprobe" -cp "$SCRATCH/bcprobe/bcprov.jar" \
  "$REPO/docs/evidence/2026-10-05-core-drop-duplicate-checks/Probe.java"
java -cp "$SCRATCH/bcprobe/bcprov.jar:$SCRATCH/bcprobe" Probe
```

Expected output:

```
parsed: BEROctetString
refused: org.bouncycastle.asn1.ASN1Exception: unknown object encountered in constructed OCTET STRING: class org.bouncycastle.asn1.DERUTF8String
refused: java.io.IOException: unknown object encountered: class org.bouncycastle.asn1.DERUTF8String
```

Reproduce the contentType experiment on the commit that added this folder
(the patch removes the core's comparison; revert it afterwards):

```sh
git -C "$REPO" apply docs/evidence/2026-10-05-core-drop-duplicate-checks/without-content-type-match.patch
CARGO_TARGET_DIR="$SCRATCH/target" cargo test --locked --all-features \
  --manifest-path "$REPO/rust/Cargo.toml" -p apple-purchase-receipt-verifier \
  --test conformance --test receipt_negative --no-fail-fast
git -C "$REPO" apply -R docs/evidence/2026-10-05-core-drop-duplicate-checks/without-content-type-match.patch
```

Expected: `conformance` 389 passed, 1 failed
(`receipt/reject-a-content-type-attribute-that-differs-from-the-econtent-type`);
`receipt_negative` 40 passed.
