# Roadmap — apple-purchase-verification

Milestone status lives here (see [PLAN.md](./PLAN.md) §4 for the full plan).
Delete an item in the same commit that ships it.

## Next

- **Real receipt fixtures** (PLAN D6): owner to supply real production +
  sandbox receipts (and ideally a StoreKit-Test/Xcode receipt) as checked-in
  fixtures; add byte-level regression tests over them.
- **Publishing prep** (PLAN D1): confirm license (MIT assumed), finalize
  coordinates (`io.github.emindeniz99` / npm / PyPI names), CI matrix on the
  D2 version floors (Java 8/11/17/21; Node 20/22/24; Python 3.9–3.13).

- **Node implementation** (`node/`): port the two verifiers per PLAN §2 with
  `node:crypto` (`X509Certificate`, `verify`), minimal deps; port the test
  PKI generator and the failure-mode test matrix from `java/`.
- **Python implementation** (`python/`): same, on the `cryptography` package
  (+ `asn1crypto` if needed for the receipt payload).
- **Cross-language fixture parity**: generate one checked-in fixture set
  (fake-Apple PKI + signed JWS + signed PKCS#7 receipt) all three
  implementations must verify byte-identically.
- **CI**: per-language workflow under `.github/workflows/` running each
  test suite (match the existing per-project workflow style).

## Later / hardening

- Optional OCSP revocation checking (opt-in "online mode", like the official
  library) for consumers who accept Apple calls.
- Check a receipt-signing marker OID on the PKCS#7 signer cert as an extra
  purpose check (mirror of the JWS marker-OID rule; needs a corpus of real
  receipts to confirm which OID Apple stamps consistently).
- `AppTransaction` / renewal-info convenience types beyond the core
  transaction payload fields.
- Example integration snippet: "client sends `jwsRepresentation` → backend
  verifies → backend records transactionId (replay guard) → unlock product".
