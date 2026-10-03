package io.github.emindeniz99.applepurchasereceiptverifier.interop

import io.github.emindeniz99.applepurchasereceiptverifier.{Config, Environment, Failure, Reason, VerificationResult, Verifier}
import org.junit.jupiter.api.Assertions.{assertEquals, assertFalse, assertNull, assertTrue, fail}
import org.junit.jupiter.api.Test

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.security.cert.{CertificateFactory, X509Certificate}
import scala.jdk.CollectionConverters.*

/** Proves the library is usable from Scala 3 exactly as a Scala consumer
  * would use it: a [[VerificationResult]] turned into an `Option` or an
  * `Either`, an exhaustive `match` over [[Reason]], and the same three
  * checks the Java, Node, Python and Swift suites run against fixtures/.
  * See jvm-interop/README.md for why this module exists and is not
  * published.
  */
class ScalaInteropTest:

  private val publicReceipts: Path = Paths.get("..", "fixtures", "public-receipts")
  private val generatedFixtures: Path = Paths.get("..", "fixtures", "generated")

  private def receiptBase64(name: String): String =
    new String(Files.readAllBytes(publicReceipts.resolve(s"$name.b64")), StandardCharsets.US_ASCII).trim

  private def generatedBytes(name: String): Array[Byte] =
    Files.readAllBytes(generatedFixtures.resolve(name))

  private def generatedText(name: String): String =
    new String(generatedBytes(name), StandardCharsets.US_ASCII).trim

  private def cert(name: String): X509Certificate =
    CertificateFactory
      .getInstance("X.509")
      .generateCertificate(new ByteArrayInputStream(generatedBytes(name)))
      .asInstanceOf[X509Certificate]

  // The idiomatic Scala view of a result: exactly one of payload() and
  // failure() is set, which is what Either expresses.
  extension [T](result: VerificationResult[T])
    private def toEither: Either[Failure, T] =
      if result.verified() then Right(result.payload()) else Left(result.failure())

  @Test
  def verifiesTheGenuineSandboxReceiptAgainstTheBuiltInAppleRoots(): Unit =
    val verifier = Verifier.create(Config.defaults())
    verifier.verifyReceipt(receiptBase64("receipt-sandbox-g5")).toEither match
      case Right(receipt) =>
        assertEquals("ProductionSandbox", receipt.receiptType())
        assertEquals("dev.bonzer.weeka.app", receipt.bundleId())
        assertEquals(2, receipt.inApp().size())
      case Left(failure) => fail(s"expected a verified receipt, got $failure")

  @Test
  def verifiesTheSharedJwsTransactionFixture(): Unit =
    val root = cert("jws-root.der")
    // Scala's Predef conversions don't reach java.util.Collection the way
    // scala.jdk.CollectionConverters does — .asJava is the idiomatic Scala
    // 3 way to hand a Scala Set to a Java API expecting a Java collection.
    val verifier = Verifier.create(Config.builder().roots(Set(root).asJava).build())
    val json = verifier.verifySignedData(generatedText("transaction.jws")).toEither match
      case Right(payload) => payload.json()
      case Left(failure)  => fail(s"expected a verified JWS, got $failure")
    // The library returns the signed JSON unchanged; parsing it is the
    // caller's job, so a substring check stands in for a JSON library.
    assertTrue(json.contains("\"transactionId\":\"2000000000000001\""), json)
    assertTrue(json.contains("\"productId\":\"com.example.app.pro\""), json)

  @Test
  def aFailingVerificationSurfacesItsReasonThroughTheResult(): Unit =
    val verifier = Verifier.create(Config.defaults())
    val result = verifier.verifyReceipt(receiptBase64("receipt-xcode-with-purchases"))
    assertFalse(result.verified())
    val reason = result.toEither.left.map(_.reason())
    assertEquals(Left(Reason.UNTRUSTED_CHAIN), reason)

  @Test
  def nullSafetyAtTheJavaBoundaryOnReceiptPayloadAccessors(): Unit =
    val result = Verifier.create(Config.defaults()).verifyReceipt(receiptBase64("receipt-sandbox-g5"))
    // Scala has no platform-type distinction for Java return values the way
    // Kotlin does, so the boundary risk is a plain possible-NPE unless the
    // caller checks. Option(...) is the idiomatic check.
    val receipt = Option(result.payload()).getOrElse(fail("expected a verified receipt"))
    assertNull(result.failure())
    // expirationDateMs() is really null here (attribute 21 is VPP-only and
    // absent from this fixture).
    assertEquals(None, Option(receipt.expirationDateMs()))
    assertEquals(Some(Environment.SANDBOX), Option(receipt.environment()))
    assertEquals("dev.bonzer.weeka.app", receipt.bundleId())

  @Test
  def reasonIsMatchedExhaustivelyInAMatchExpression(): Unit =
    val failure = new Failure(Reason.UNTRUSTED_CHAIN, "test", null)
    // No wildcard case below: relies on Scala 3's exhaustivity check for
    // Java enums. See jvm-interop/README.md for whether the compiler
    // actually enforced this (warning vs. error) as observed here.
    val description = failure.reason() match
      case Reason.MALFORMED                   => "malformed"
      case Reason.TOO_LARGE                   => "too large"
      case Reason.INVALID_SIGNATURE           => "bad signature"
      case Reason.UNTRUSTED_CHAIN             => "untrusted chain"
      case Reason.INVALID_CERTIFICATE         => "bad cert"
      case Reason.INVALID_CERTIFICATE_PURPOSE => "wrong purpose"
      case Reason.UNREADABLE_PAYLOAD          => "unreadable payload"
      case Reason.INTERNAL_ERROR              => "internal error"
    assertEquals("untrusted chain", description)
