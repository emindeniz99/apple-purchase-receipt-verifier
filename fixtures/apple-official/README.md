# Apple official test fixtures (vendored)

Test fixtures copied verbatim from Apple's official
[`app-store-server-library-java`](https://github.com/apple/app-store-server-library-java)
(commit `d2c00cb7a567083deba1496e1b40a2e1f39c0b1f`), MIT-licensed,
Copyright 2023 Apple Inc. Vendored per PLAN.md D1 ("vendoring is ok") so
every language implementation in this project verifies the exact bytes
Apple's own test suite uses — cross-library parity for free.

| Folder | Contents | How we use it |
|--------|----------|---------------|
| `certs/` | Apple's test CA / intermediate / leaf (public certs only — their `.key` / `.p8` private keys are deliberately **not** vendored; we never need to sign) plus invalid-OID / invalid-chain variants | `testCA.der` is the trust anchor for verifying `mock_signed_data/*` |
| `mock_signed_data/` | Compact JWS fixtures signed by the test CA: `transactionInfo`, `renewalInfo`, `testNotification` (bundle `com.example`, Sandbox), `wrongBundleId`, `missingX5CHeaderClaim`, `legacyTransaction` | Positive + negative JWS verification cases |
| `xcode/` | Genuine Xcode/StoreKit-Test-generated receipts and signed payloads (bundle `com.example.naturelab.backyardbirds.example`) | Prove pinning: none of these may verify against real Apple roots (Xcode signs locally — 1-cert x5c, local receipt signer) |

These complement (not replace) the generated fake-Apple-PKI fixtures in
each language's test suite, and the real production/sandbox receipt corpus
still to come (ROADMAP / PLAN D6).
