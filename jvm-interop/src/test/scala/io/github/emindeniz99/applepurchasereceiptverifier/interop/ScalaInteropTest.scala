package io.github.emindeniz99.applepurchasereceiptverifier.interop

import io.github.emindeniz99.applepurchasereceiptverifier.{AppleRootCerts, Environment, VerificationException}
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier
import org.junit.jupiter.api.Assertions.{assertEquals, assertNull}
import org.junit.jupiter.api.Test

import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.util.EnumSet
import scala.jdk.CollectionConverters.*

/** Proves the library is usable from Scala 3 exactly as a Scala consumer
  * would use it: idiomatic try/catch on [[VerificationException]], an
  * exhaustive `match` over [[Reason]], and the same three checks the Java,
  * Node, Python and Swift suites run against fixtures/. See
  * jvm-interop/README.md for why this module exists and is not published.
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

  @Test
  def verifiesTheGenuineSandboxReceiptAgainstTheBuiltInAppleRoots(): Unit =
    val verifier = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app")
    val receipt = verifier.verify(receiptBase64("receipt-sandbox-g5"))
    assertEquals("ProductionSandbox", receipt.receiptType())
    assertEquals(2, receipt.inAppPurchases().size())

  @Test
  def verifiesTheSharedJwsTransactionFixture(): Unit =
    val root = cert("jws-root.der")
    // Scala's Predef conversions don't reach java.util.Set the way
    // scala.jdk.CollectionConverters does — .asJava is the idiomatic Scala
    // 3 way to hand a Scala Set to a Java API expecting java.util.Set.
    val verifier = new JwsVerifier(Set(root).asJava, "com.example.app", EnumSet.of(Environment.SANDBOX))
    val payload = verifier.verifyTransaction(generatedText("transaction.jws"))
    assertEquals("2000000000000001", payload.transactionId())
    assertEquals("com.example.app.pro", payload.productId())

  @Test
  def aFailingVerificationSurfacesItsReasonThroughIdiomaticTryCatch(): Unit =
    val verifier = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "*")
    var caught: Reason = null
    try verifier.verify(receiptBase64("receipt-xcode-with-purchases"))
    catch case e: VerificationException => caught = e.reason()
    assertEquals(Reason.INVALID_CHAIN, caught)

  @Test
  def nullSafetyAtTheJavaBoundaryOnAppReceiptAccessors(): Unit =
    val verifier = new ReceiptVerifier(AppleRootCerts.receiptRoots(), "dev.bonzer.weeka.app")
    val receipt = verifier.verify(receiptBase64("receipt-sandbox-g5"))
    // expirationDate() is really null here (attribute 21 is VPP-only and
    // absent from this fixture) — Scala has no platform-type distinction
    // for Java return values the way Kotlin does, so the boundary risk is
    // a plain possible-NPE unless the caller checks, which this does.
    val expirationDate = receipt.expirationDate()
    assertNull(expirationDate)
    assertEquals("dev.bonzer.weeka.app", receipt.bundleId())

  @Test
  def reasonIsMatchedExhaustivelyInAMatchExpression(): Unit =
    val e = new VerificationException(Reason.WRONG_BUNDLE_ID, "test")
    // No wildcard case below: relies on Scala 3's exhaustivity check for
    // Java enums. See jvm-interop/README.md for whether the compiler
    // actually enforced this (warning vs. error) as observed here.
    val description = e.reason() match
      case Reason.INVALID_JWS_FORMAT           => "bad jws"
      case Reason.INVALID_CERTIFICATE          => "bad cert"
      case Reason.INVALID_CERTIFICATE_PURPOSE  => "wrong purpose"
      case Reason.INVALID_CHAIN                => "bad chain"
      case Reason.INVALID_SIGNATURE            => "bad signature"
      case Reason.WRONG_BUNDLE_ID              => "wrong bundle"
      case Reason.WRONG_ENVIRONMENT            => "wrong environment"
      case Reason.WRONG_APP_APPLE_ID           => "wrong app id"
      case Reason.INVALID_RECEIPT_FORMAT       => "bad receipt"
      case Reason.DEVICE_HASH_MISMATCH         => "device mismatch"
      case Reason.STALE_PAYLOAD                => "stale"
    assertEquals("wrong bundle", description)
