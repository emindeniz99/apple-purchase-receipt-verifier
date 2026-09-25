# Java binding bake-off: shared spec (research spike, NOT product code)

Goal: compare four ways to expose the Rust verifier core to Java at the SAME scope.
The UniFFI version already exists; you build one of: jni-rs, flapigen, SWIG.

## Hard rules
- Never modify anything under $REPO (read-only). Depend on the core by path:
  `aprv = { package = "apple-purchase-receipt-verifier", path = "$REPO/rust" }`
  (the C ABI crate is $REPO/rust/ffi; build it into YOUR OWN target dir with CARGO_TARGET_DIR).
- Work only in your folder: $B/<approach>/ where B=$SCRATCH/java-bakeoff
- Use your own CARGO_TARGET_DIR=$B/<approach>/target. Build Rust with --release.
- No verification logic in Java or in glue: only conversion. The Rust core decides everything.
- Do NOT run timing benchmarks (other agents share the CPU). Just make Bench.java compile and run once briefly (n=50) to prove it works. The owner's session times everything sequentially later.
- Do not use cd-compound shell commands; use absolute paths, `env -C DIR cmd`, `cargo --manifest-path`, `mvn -f`.

## Toolchains (already installed)
- JDK 8:  $SCRATCH/jdk8/jdk8u504-b01/bin/{java,javac}
- JDK 17: $SCRATCH/jdk17/jdk-17.0.20.1+1/bin/{java,javac}
- JDK 21: /usr/bin/java, /usr/bin/javac (JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64)
- Maven: mvn (Maven Central reachable). swig 4.2.0: swig. Rust: cargo 1.94.1. crates.io reachable.
- Compile Java with `javac --release 8` (JDK 21 javac) so the same classes run on 8/17/21.

## Fixtures (read-only)
F=$REPO/fixtures
- genuine receipt (base64, strip whitespace): $F/public-receipts/receipt-sandbox-g5.b64 — bundle id dev.bonzer.weeka.app, 2 in-app purchases, verify against Apple's built-in roots.
- generated receipt DER $F/generated/receipt.der with root $F/generated/receipt-root.der, bundle com.example.app
- JWS $F/generated/transaction.jws (trim) with root $F/generated/jws-root.der, bundle com.example.app, env Sandbox

## Required Java API (package `bakeoff.<approach>`), all public, with Javadoc on every public class/method
```
enum Environment { PRODUCTION, SANDBOX, XCODE, LOCAL_TESTING }
enum Reason { INVALID_JWS_FORMAT, INVALID_CERTIFICATE, INVALID_CERTIFICATE_PURPOSE, INVALID_CHAIN,
              INVALID_SIGNATURE, WRONG_BUNDLE_ID, WRONG_ENVIRONMENT, WRONG_APP_APPLE_ID,
              INVALID_RECEIPT_FORMAT, DEVICE_HASH_MISMATCH, MALFORMED_REQUEST, INTERNAL_ERROR, REQUEST_TOO_LARGE }
class VerificationException extends Exception { Reason reason(); String detail(); }   // checked
class ConfigurationException extends RuntimeException
final class InAppPurchase { productId, transactionId, originalTransactionId: String (nullable);
                            quantity, purchaseDateMs, expiresDateMs: Long (nullable) }   // getters, immutable
final class AppReceipt { receiptType, bundleId, appVersion, originalAppVersion: String;
                         opaqueValue, sha1Hash: byte[]; creationDateMs: Long; List<InAppPurchase> inAppPurchases }
final class TransactionPayload { bundleId, environment, productId, transactionId: String; signedDate, purchaseDate: Long; claimsJson: String }
final class ReceiptVerifier implements AutoCloseable {
  ReceiptVerifier(String bundleId)                        // Apple's pinned roots
  ReceiptVerifier(String bundleId, List<byte[]> roots)
  AppReceipt verify(byte[] der) throws VerificationException
  AppReceipt verifyBase64(String b64) throws VerificationException }
final class JwsVerifier implements AutoCloseable {
  JwsVerifier(String bundleId, Set<Environment> envs, Long appAppleId /*nullable*/, List<byte[]> roots /*nullable = Apple*/)
  TransactionPayload verifyTransaction(String jws) throws VerificationException }
final class VerifyReceiptEndpoint implements AutoCloseable {
  VerifyReceiptEndpoint(Environment env)   // Apple roots
  String verifyReceiptJson(String body)    // never throws
  VerifyReceiptResult verifyReceiptResult(String body) }
final class VerifyReceiptResult implements AutoCloseable (or plain value) {
  long status(); boolean verified(); AppReceipt receipt() /*nullable*/; Reason failureReason() /*nullable*/;
  String toJson(); String toJsonIn(Environment env) /* re-render WITHOUT re-verifying */ }
```
All verifier objects must be safe to share across threads (test: 8 threads x 100 calls on one ReceiptVerifier).

## Required programs
1. `Demo.java` prints, and must print exactly these facts:
   - genuine g5: bundleId, IAP count 2, first productId, first purchaseDateMs
   - generated DER with custom root: bundleId com.example.app, creationDateMs 1722945600000
   - wrong bundle id → VerificationException with reason WRONG_BUNDLE_ID
   - JWS: productId com.example.app.pro, signedDate 1722945600000; PRODUCTION-only verifier → WRONG_ENVIRONMENT
   - Endpoint PRODUCTION with body {"receipt-data":"<g5>"}: verifyReceiptJson → {"status":21007}; result.status()==21007,
     verified()==true, receipt().bundleId, toJsonIn(SANDBOX) starts with {"environment":"Sandbox","receipt":
   - body "not json" → status 21002, failureReason MALFORMED_REQUEST, no exception
   - bad root bytes → ConfigurationException
   - 8 threads x 100 calls on one shared ReceiptVerifier: all succeed
   Run Demo on JDK 8, 17 and 21. All must pass.
2. `Bench.java`: 10,000 warm-up calls, then 3 rounds x 10,000 of (a) ReceiptVerifier.verifyBase64(g5) and
   (b) JwsVerifier.verifyTransaction(jws); prints "<approach> round N: receipt X us, jws Y us". Run it once with a
   system property -Dbench.n=50 to prove it works, nothing more.
3. `run.sh`: builds everything from scratch and runs Demo on 8/17/21, then Bench (full) on a JDK given as $1.

## Report back (concise, under 500 words)
- PASS/FAIL per Demo fact per JDK.
- Line counts (wc -l) split into: hand-written Rust glue, hand-written Java, interface/config files, generated code.
- Count of `unsafe` in hand-written Rust.
- Runtime dependencies of the Java side (jars) and the native lib size (stripped).
- What was painful, what the API looks like from Java (paste the public signatures of ReceiptVerifier and VerifyReceiptResult), anything you could not do at spec scope and why.
- Exact command to run the full benchmark.
