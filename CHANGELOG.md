# Changelog

## [0.2.0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/compare/v0.1.0...v0.2.0) (2026-08-15)


### Features

* **apple-purchase-verification/java:** JWS + PKCS[#7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/issues/7) verifiers, Java 8 ([ab46484](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/ab46484799cd567d97a6d2da2fabdc90a2c7a016))
* **apple-purchase-verification/java:** local verifyReceipt-compatible endpoint ([9929922](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9929922cabcb9285cb1ed64c1427cbd4b129f626))
* **apple-purchase-verification/java:** scaffold Maven verifier lib ([e33d8e3](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/e33d8e38c053601088b5139de7af1e89c993a58f))
* **apple-purchase-verification/node:** JWS + PKCS[#7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/issues/7) verifiers, zero deps ([44f143a](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/44f143a73647babbc031a0874b87c0671355dbb1))
* **apple-purchase-verification/node:** TypeScript migration + verifyReceipt endpoint ([c20c9ce](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c20c9ce3ae5b06cfe2d1740f93f92660b4604f5f))
* **apple-purchase-verification/python:** JWS + PKCS[#7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/issues/7) verifiers ([fe15cff](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fe15cff784d5ab4fc7179f78af8c2192e12aac09))
* **apple-purchase-verification/python:** typing + verifyReceipt endpoint ([0817dfd](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/0817dfdc9dae92148e3209b1c4cf3d928190f450))
* **apple-purchase-verification/swift:** JWS + PKCS[#7](https://github.com/emindeniz99/apple-purchase-receipt-verifier/issues/7) verifiers ([fe10e0e](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/fe10e0e1613cb5a9d6cc34405223d1592e53a3b9))
* **apple-purchase-verification/swift:** verifyReceipt endpoint + receipt_type attrs ([20ff3a0](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/20ff3a04deb006c4b1628fa68bd2436a42ce99c4))
* **apple-purchase-verification:** prod-ready pass - license, CI, hardening, D11/D12 ([07d6f3b](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/07d6f3b487164bdfcb4427f801cc4dc59b74b5a2))
* **apple-purchase-verification:** verify genuine Apple receipts (public-fixture harvest) ([581da6d](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/581da6d9bf34d352b5394d9da447c14c35447bb3))


### Bug Fixes

* **apple-purchase-verification/java:** adversarial-review fixes + forward-compat attrs ([c9121d9](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c9121d9bb4fc8441057b156ef1b83e2e11947207))
* **apple-purchase-verification/node:** fail-closed routing + unknown attributes ([9c799d6](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/9c799d640eb544fa868a6ef004860adbbe8156c2))
* **apple-purchase-verification/python:** fail-closed routing, strict CMS, helpers ([2349e99](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/2349e9959b6897bc21410177617d5f7308b3c2d9))
* **apple-purchase-verification/swift:** fail-closed routing, lenient x5c, unknown attrs ([6c315bc](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/6c315bcb11e29b0df5a27365cff52e1cd5efb917))
* **apple-purchase-verification:** close 5 LOW/INFO parity items from second review ([5898467](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/5898467892311f9f9204965bcb4957a883d74da4))
* **apple-purchase-verification:** close CRITICAL receipt-forgery hole + review findings ([f1a4ddb](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/f1a4ddbe519c6591abb9a1838ea9ab315eebf886))
* **apple-purchase-verification:** drop the production receipt fixture ([c24f9ce](https://github.com/emindeniz99/apple-purchase-receipt-verifier/commit/c24f9ce5fd8dee3f40c2203bbbfa56dd092d2ab5))
