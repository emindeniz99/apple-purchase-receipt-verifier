package io.github.emindeniz99.applepurchasereceiptverifier.interop

import io.github.emindeniz99.applepurchasereceiptverifier.AppleRootCerts
import io.github.emindeniz99.applepurchasereceiptverifier.Environment
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.EnumSet

/**
 * Proves the library is usable from Kotlin exactly as a Kotlin consumer
 * would use it: idiomatic try/catch on [VerificationException], an
 * exhaustive `when` over [Reason], and the same three checks the Java,
 * Node, Python and Swift suites run against fixtures/. See
 * jvm-interop/README.md for why this module exists and is not published.
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

    @Test
    fun `verifies the genuine sandbox receipt against the built-in Apple roots`() {
        val verifier = ReceiptVerifier(AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app")
        val receipt = verifier.verify(receiptBase64("receipt-sandbox-g5"))
        assertEquals("ProductionSandbox", receipt.receiptType())
        assertEquals(2, receipt.inAppPurchases().size)
    }

    @Test
    fun `verifies the shared JWS transaction fixture`() {
        val root = cert("jws-root.der")
        val verifier = JwsVerifier(setOf(root), "com.example.app", EnumSet.of(Environment.SANDBOX))
        val payload = verifier.verifyTransaction(generatedText("transaction.jws"))
        assertEquals("2000000000000001", payload.transactionId())
        assertEquals("com.example.app.pro", payload.productId())
    }

    @Test
    fun `overload selection stands in for named or default arguments -- Kotlin cannot use either against a Java API`() {
        // JwsVerifier has no builder; a Kotlin caller reaches for named
        // arguments here (5-arg ctor, naming just appAppleId/maxSignedAge)
        // or default arguments (call the 2-arg ctor and skip the trailing
        // params). Only the second works, and NOT because of anything
        // fixable in java/pom.xml: Kotlin categorically refuses named-
        // argument syntax against any Java-declared function, regardless
        // of MethodParameters / javac -parameters. Confirmed two ways —
        // see jvm-interop/README.md "Findings" for both:
        //   1. `JwsVerifier(trustedRoots = ..., bundleId = ..., ...)`
        //      still fails after java/pom.xml gained
        //      <parameters>true</parameters> (verified with javap -v: the
        //      class file DOES carry real names now).
        //   2. The same named-argument syntax against a plain JDK class
        //      (java.awt.Point(x = 1, y = 2), nothing to do with our jar)
        //      fails identically, with the compiler's own diagnostic:
        //      "Named arguments are prohibited for non-Kotlin functions."
        // So -parameters is worth having for other reasons (real names in
        // IDE hints, error messages, and Java/Kotlin reflection over this
        // jar) but it does not and cannot unlock this. This is what a
        // Kotlin consumer actually falls back to instead.
        val root = cert("jws-root.der")
        val verifier = JwsVerifier(setOf(root), "com.example.app", EnumSet.of(Environment.SANDBOX))
        val payload = verifier.verifyTransaction(generatedText("transaction.jws"))
        assertEquals("2000000000000001", payload.transactionId())
    }

    @Test
    fun `a failing verification surfaces its reason through idiomatic try-catch`() {
        val verifier = ReceiptVerifier(AppleRootCerts.receiptRoots(), "*")
        var caught: Reason? = null
        try {
            verifier.verify(receiptBase64("receipt-xcode-with-purchases"))
        } catch (e: VerificationException) {
            caught = e.reason()
        }
        assertEquals(Reason.INVALID_CHAIN, caught)
    }

    @Test
    fun `null-safety at the Java boundary on AppReceipt accessors`() {
        val verifier = ReceiptVerifier(AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app")
        val receipt = verifier.verify(receiptBase64("receipt-sandbox-g5"))
        // AppReceipt's Java accessors carry no nullability annotations, so
        // Kotlin sees them as platform types (String!, Instant!) rather than
        // definite non-null — the caller decides. expirationDate() really is
        // null here (attribute 21 is VPP-only and absent from this fixture),
        // so treating the platform type as nullable is the only safe choice;
        // treating it as non-null would NPE at unwrap.
        val expirationDate = receipt.expirationDate()
        assertNull(expirationDate)
        val bundleId: String? = receipt.bundleId()
        assertEquals("dev.bonzer.weeka.app", bundleId)
    }

    @Test
    fun `Reason is matched exhaustively in a when expression`() {
        val e = VerificationException(Reason.WRONG_BUNDLE_ID, "test")
        // No `else` branch below: this compiles only if every current
        // Reason constant is listed. If Apple's Reason enum ever grows a
        // constant, this file fails to compile until updated — that is
        // exhaustiveness doing its job, not a bug in the test.
        val description: String = when (e.reason()) {
            Reason.INVALID_JWS_FORMAT -> "bad jws"
            Reason.INVALID_CERTIFICATE -> "bad cert"
            Reason.INVALID_CERTIFICATE_PURPOSE -> "wrong purpose"
            Reason.INVALID_CHAIN -> "bad chain"
            Reason.INVALID_SIGNATURE -> "bad signature"
            Reason.WRONG_BUNDLE_ID -> "wrong bundle"
            Reason.WRONG_ENVIRONMENT -> "wrong environment"
            Reason.WRONG_APP_APPLE_ID -> "wrong app id"
            Reason.INVALID_RECEIPT_FORMAT -> "bad receipt"
            Reason.DEVICE_HASH_MISMATCH -> "device mismatch"
            Reason.STALE_PAYLOAD -> "stale"
        }
        assertEquals("wrong bundle", description)
    }
}
