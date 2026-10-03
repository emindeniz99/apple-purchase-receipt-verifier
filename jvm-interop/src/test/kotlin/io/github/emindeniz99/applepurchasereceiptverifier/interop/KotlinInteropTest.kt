package io.github.emindeniz99.applepurchasereceiptverifier.interop

import io.github.emindeniz99.applepurchasereceiptverifier.Config
import io.github.emindeniz99.applepurchasereceiptverifier.Environment
import io.github.emindeniz99.applepurchasereceiptverifier.Failure
import io.github.emindeniz99.applepurchasereceiptverifier.InAppPurchase
import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload
import io.github.emindeniz99.applepurchasereceiptverifier.Reason
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Clock

/**
 * Proves the library is usable from Kotlin exactly as a Kotlin consumer
 * would use it: a [VerificationResult] read with `?:` rather than `!!`, an
 * exhaustive `when` over [Reason], JSpecify nullness at the boundary, and
 * the same three checks the Java, Node, Python and Swift suites run against
 * fixtures/. See jvm-interop/README.md for why this module exists and is
 * not published.
 */
class KotlinInteropTest {

    private val publicReceipts: Path = Paths.get("..", "fixtures", "public-receipts")
    private val generatedFixtures: Path = Paths.get("..", "fixtures", "generated")

    private fun receiptBase64(name: String): String =
        String(Files.readAllBytes(publicReceipts.resolve("$name.b64")), StandardCharsets.US_ASCII).trim()

    private fun generatedBytes(name: String): ByteArray = Files.readAllBytes(generatedFixtures.resolve(name))

    private fun generatedText(name: String): String =
        String(generatedBytes(name), StandardCharsets.US_ASCII).trim()

    private fun cert(name: String): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(generatedBytes(name))) as X509Certificate

    /** The payload of a result that must have verified, or the test fails with the reason. */
    private fun <T : Any> VerificationResult<T>.payloadOrFail(): T =
        payload() ?: fail("expected a verified result, got ${failure()}")

    @Test
    fun `verifies the genuine sandbox receipt against the built-in Apple roots`() {
        val verifier = Verifier.create(Config.defaults())
        val receipt = verifier.verifyReceipt(receiptBase64("receipt-sandbox-g5")).payloadOrFail()
        assertEquals("ProductionSandbox", receipt.receiptType())
        assertEquals("dev.bonzer.weeka.app", receipt.bundleId())
        assertEquals(2, receipt.inApp().size)
    }

    @Test
    fun `verifies the shared JWS transaction fixture`() {
        val verifier = Verifier.create(Config.builder().roots(setOf(cert("jws-root.der"))).build())
        val payload: JsonPayload = verifier.verifySignedData(generatedText("transaction.jws")).payloadOrFail()
        // The library returns the signed JSON unchanged; parsing it is the
        // caller's job, so a substring check stands in for a JSON library.
        assertTrue(payload.json().contains("\"transactionId\":\"2000000000000001\""), payload.json())
        assertTrue(payload.json().contains("\"productId\":\"com.example.app.pro\""), payload.json())
    }

    @Test
    fun `the Config builder chains from Kotlin, standing in for named arguments Kotlin cannot use on a Java API`() {
        // Kotlin refuses named-argument syntax at any Java-declared function
        // ("Named arguments are prohibited for non-Kotlin functions"), so a
        // Java API with optional settings needs a builder to read well from
        // Kotlin. 0.7's Config is one: each setting is named at the call site
        // and the ones left out keep their defaults. See jvm-interop/README.md
        // "Findings" for how the named-argument rule was established.
        val root = cert("jws-root.der")
        val config = Config.builder()
            .roots(setOf(root))
            .clock(Clock.systemUTC())
            .build()
        val roots: Set<X509Certificate> = config.roots()
        assertEquals(setOf(root), roots)
        val payload = Verifier.create(config).verifySignedData(generatedText("transaction.jws")).payloadOrFail()
        assertTrue(payload.json().contains("\"transactionId\":\"2000000000000001\""), payload.json())
    }

    @Test
    fun `a failing verification surfaces its reason through the result, with no exception`() {
        val verifier = Verifier.create(Config.defaults())
        val result = verifier.verifyReceipt(receiptBase64("receipt-xcode-with-purchases"))
        assertFalse(result.verified())
        assertNull(result.payload())
        val failure: Failure = result.failure() ?: fail("expected a failure")
        assertEquals(Reason.UNTRUSTED_CHAIN, failure.reason())
        val message: String = failure.message()
        assertTrue(message.isNotEmpty())
    }

    @Test
    fun `JSpecify nullness reaches Kotlin, so accessors are nullable or non-null and never platform types`() {
        val result: VerificationResult<ReceiptPayload> =
            Verifier.create(Config.defaults()).verifyReceipt(receiptBase64("receipt-sandbox-g5"))

        // payload() and failure() are @Nullable: exactly one is set. Kotlin
        // types them ReceiptPayload? and Failure?, so the caller has to
        // handle the other case (`?:` here) instead of reaching for `!!`.
        val receipt: ReceiptPayload = result.payload() ?: fail("expected a verified result")
        val failure: Failure? = result.failure()
        assertNull(failure)

        // Every receipt-attribute accessor is @Nullable: a receipt carries
        // only the attributes that apply to it. Kotlin therefore types these
        // String? / Long?, and expirationDateMs() really is null here
        // (attribute 21 is VPP-only and absent from this fixture).
        val receiptType: String? = receipt.receiptType()
        assertEquals("ProductionSandbox", receiptType)
        val environment: Environment? = receipt.environment()
        assertEquals(Environment.SANDBOX, environment)
        val bundleId: String? = receipt.bundleId()
        assertEquals("dev.bonzer.weeka.app", bundleId)
        val expirationDateMs: Long? = receipt.expirationDateMs()
        assertNull(expirationDateMs)

        // Everything the package's @NullMarked leaves unannotated is
        // definitely non-null, so it lands in a non-null Kotlin type with no
        // `!!` and no `?:` at the boundary. No expression in this file uses
        // `!!`, which is the ergonomic claim the annotations exist to make.
        val purchases: List<InAppPurchase> = receipt.inApp()
        assertEquals(2, purchases.size)
        val productId: String? = purchases[0].productId()
        assertNotNull(productId)
        val json: String = receipt.toJson()
        assertTrue(json.startsWith("{\"receipt_type\":\"ProductionSandbox\""), json)
    }

    // Why there is no negative test beside the one above, and why that is a
    // property of Kotlin rather than an omission:
    //
    // A negative test would have to be source that FAILS to compile, and
    // every file in this module is compiled together — one such file fails
    // the whole module's test-compile, so it cannot live here. A test that
    // merely compiles cannot distinguish the three possible states either:
    // a platform type (`String!`) satisfies both `String` and `String?`, so
    // the positive assignments above would still compile if the annotations
    // were absent or ignored.
    //
    // So the negative direction was verified by hand instead, on the 0.7
    // jar with Kotlin 2.4.20 and -Xjspecify-annotations=strict (2026-09-27).
    // Dropping these two declarations into a scratch file under
    // src/test/kotlin, with the imports this file already has:
    //
    //     fun probeNullable(r: ReceiptPayload): String = r.receiptType()
    //     fun probeNonNull(): Int? = Config.defaults().roots()?.size
    //
    // produced both halves of the proof, and nothing else:
    //
    //     error: Return type mismatch: expected 'String', actual 'String?'.
    //     warning: Unnecessary safe call on a non-null receiver of type
    //              '(Mutable)Set<X509Certificate>'.
    //
    // The error is @Nullable being enforced; the warning is @NullMarked's
    // non-null default being enforced. Note what is NOT on this module's
    // classpath while both fire: org.jspecify:jspecify itself. It is an
    // <optional> dependency of the library, so it is not transitive and a
    // consumer never resolves it — Kotlin reads the annotation names out of
    // the class files. Re-run the probe if you need to see it again.

    @Test
    fun `Reason is matched exhaustively in a when expression`() {
        val failure = Failure(Reason.UNTRUSTED_CHAIN, "test", null)
        // No `else` branch below: this compiles only if every current
        // Reason constant is listed. If the library's Reason enum ever grows
        // a constant, this file fails to compile until updated — that is
        // exhaustiveness doing its job, not a bug in the test.
        val description: String = when (failure.reason()) {
            Reason.MALFORMED -> "malformed"
            Reason.TOO_LARGE -> "too large"
            Reason.INVALID_SIGNATURE -> "bad signature"
            Reason.UNTRUSTED_CHAIN -> "untrusted chain"
            Reason.INVALID_CERTIFICATE -> "bad cert"
            Reason.INVALID_CERTIFICATE_PURPOSE -> "wrong purpose"
            Reason.UNREADABLE_PAYLOAD -> "unreadable payload"
            Reason.INTERNAL_ERROR -> "internal error"
        }
        assertEquals("untrusted chain", description)
    }
}
