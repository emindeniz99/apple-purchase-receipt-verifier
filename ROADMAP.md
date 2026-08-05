# Roadmap — apple-purchase-verification

Milestone status lives here (see [PLAN.md](./PLAN.md) §4 for the full plan).
Delete an item in the same commit that ships it.

## Next

- **Real receipt fixtures** (PLAN D6): owner to supply real production +
  sandbox receipts (and ideally a StoreKit-Test/Xcode receipt) as checked-in
  fixtures; add byte-level regression tests over them in all four suites.
  Also use the corpus to confirm undocumented attribute ids
  (`is_trial_period`, `adam_id`, `version_external_identifier`) so
  COMPARISON.md's "not produced" list can shrink.
- **Mac App Store receipt fixture**: the harvest (fixtures/public-receipts/,
  done ✅ — genuine production + sandbox + legacy receipts verify in all four
  languages) covered iOS; a genuine macOS receipt is still missing.
- **Java 8 runtime CI leg**: the artifact is verified Java 8 bytecode and
  CI tests on JDK 11/17/21; add a surefire `jvm` override leg that runs
  the suite on a real Temurin 8 runtime.
- **Publishing prep** (PLAN D1): finalize coordinates
  (`io.github.emindeniz99` / npm / PyPI / SwiftPM names) and publish at
  graduation. CI + license are in place (`.github/workflows/`, LICENSE) —
  the workflows live inside this folder deliberately and activate when the
  project graduates to its own repository.

## Upstream contribution (after publishing)

Apple's official `app-store-server-library-{java,node,python,swift}` verify
JWS locally but their `ReceiptUtility` only *extracts* transaction ids from
legacy PKCS#7 receipts — docstrings state "NO validation is performed".
Our verified legacy-receipt validation is a natural upstream feature:

- **PR into `apple/app-store-server-library-java`**: port `ReceiptVerifier`
  to the upstream codebase. Upstream requires Java 11+, so the PR is a
  Java 11-idiom port; our Java 8-compatible build stays canonical in this
  repo for enterprise consumers upstream won't serve (PLAN D2).
- **PRs into `-node`, `-python`, and `-swift`**: same contribution, now that
  all four of our implementations are fixture-parity-proven.

### Issues worth filing upstream (notes from reading their sources)

- **Feature request (all four libs)**: validated legacy-receipt parsing.
  `ReceiptUtility.extractTransactionId*` returns attacker-controllable data
  from an unverified blob; the docstring warns, but the API shape invites
  misuse (extract → trust). Filing this frames our PRs.
- **Foot-gun report**: `SignedDataVerifier` silently skips ALL signature
  verification when the configured environment is XCODE / LOCAL_TESTING.
  A production service misconfigured to a test environment would accept
  forged payloads with no error. An explicit opt-in flag (e.g.
  `allowUnverifiedTestPayloads`) would make the danger visible.
- **Java 8 support question**: upstream requires Java 11; large enterprise
  fleets still run 8 (why our Java build targets it). Worth asking if a
  lowered floor or a maintained 8-compatible artifact would be accepted.

## Later / hardening

- Decide whether to support the ancient `transactionReceipt`
  (purchase-info) format at all (double-wrapped payloads are handled ✅).
- **Dev-mode environments**: Apple's `SignedDataVerifier` deliberately
  skips signature verification for XCODE / LOCAL_TESTING payloads (they
  aren't Apple-signed). Our verifiers hard-fail them on chain validation.
  If local-testing support is ever needed, add an explicit, loudly-gated
  insecure dev mode — never reachable from production config.
- Optional OCSP revocation checking (opt-in "online mode", like the official
  library) for consumers who accept Apple calls.
- Check a receipt-signing marker OID on the PKCS#7 signer cert as an extra
  purpose check (mirror of the JWS marker-OID rule; needs the real-receipt
  corpus to confirm which OID Apple stamps consistently).
- Notification-envelope convenience (typed `verifyNotification` that also
  verifies nested `signedTransactionInfo` / `signedRenewalInfo`) — today
  `verifyRaw` covers notifications with caller-side claim checks.
- Example integration snippet: "client sends `jwsRepresentation` → backend
  verifies → backend records transactionId (replay guard) → unlock product".
