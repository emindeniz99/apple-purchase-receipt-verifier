package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationException.Reason;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The size a public entry point will look at, and the JSON shape it will read,
 * are bounded before anything is decoded.
 *
 * <p>Both bounds guard the same promise: "every entry point throws the checked
 * {@code VerificationException}, never an unchecked one" (README). An
 * {@link OutOfMemoryError} is not a {@code VerificationException} and cannot be
 * caught meaningfully, so an input large enough to provoke one breaks the
 * promise on exactly the hostile input the promise exists for: a 64 MB JWS
 * under {@code -Xmx256m} did. Nesting is the same story with a smaller input:
 * the JWS header is parsed before any signature check, and the depth guard
 * behind that parse is a Jackson <em>default</em>, which a host BOM pinning an
 * older Jackson 2 removes silently.
 *
 * <p>Every oversize case here is built so that the guard is the only thing that
 * can produce the answer asserted: the input either verifies without it, or is
 * refused for a different, named reason. An oversize input that was merely
 * malformed would be refused with or without the bound and would prove
 * nothing.
 */
class InputSizeBoundsTest {

    private static final Path FIXTURES = Paths.get("..", "fixtures", "generated");
    private static final String BUNDLE = "com.example.app";

    // ------------------------------------------------------------------
    // JWS
    // ------------------------------------------------------------------

    @Test
    void jwsOverTheSizeLimitIsRefusedBeforeAnySegmentIsDecoded() throws Exception {
        // A genuine JWS with a long base64url run appended to its signature
        // segment. Without the bound the whole input is read: the header
        // parses, the three certificates are decoded, the chain is built and
        // the payload is parsed, and only then is the oversized signature
        // refused as INVALID_SIGNATURE for its length. With the bound nothing
        // past the length check runs.
        String jws = genuineJws() + repeat('A', JwsVerifier.MAX_JWS_BYTES);
        VerificationException thrown =
                assertThrows(VerificationException.class, () -> jwsVerifier().verifyTransaction(jws));
        assertEquals(Reason.INVALID_JWS_FORMAT, thrown.reason());
        assertTrue(thrown.getMessage().contains("exceeds the maximum accepted size"), thrown.getMessage());
    }

    @Test
    void jwsAtTheSizeLimitIsNotRefusedForItsSize() throws Exception {
        String jws = genuineJws();
        String atLimit = jws + repeat('A', JwsVerifier.MAX_JWS_BYTES - jws.length());
        assertEquals(JwsVerifier.MAX_JWS_BYTES, atLimit.length());
        VerificationException thrown =
                assertThrows(VerificationException.class, () -> jwsVerifier().verifyTransaction(atLimit));
        assertFalse(thrown.getMessage().contains("exceeds the maximum accepted size"), thrown.getMessage());
    }

    /**
     * The nesting bound is this library's, not Jackson's: 200 is far below
     * Jackson's own default of 1000, so a port that inherited the default
     * would parse this header and answer about its missing {@code alg}.
     */
    @Test
    void jwsHeaderNestedDeeperThanTheLimitIsRefusedAsMalformed() throws Exception {
        VerificationException thrown = assertThrows(
                VerificationException.class, () -> jwsVerifier().verifyTransaction(headerJws(nestedJson(200))));
        assertEquals(Reason.INVALID_JWS_FORMAT, thrown.reason());
        assertTrue(
                thrown.getCause() instanceof StreamConstraintsException,
                "the refusal did not come from the reader constraints: " + thrown.getCause());
    }

    /** Just under the configured 64: the same shape has to get past the reader. */
    @Test
    void jwsHeaderNestedJustUnderTheLimitReachesTheAlgorithmCheck() throws Exception {
        VerificationException thrown = assertThrows(
                VerificationException.class, () -> jwsVerifier().verifyTransaction(headerJws(nestedJson(60))));
        assertEquals(Reason.INVALID_JWS_FORMAT, thrown.reason());
        assertTrue(thrown.getMessage().contains("alg must be ES256"), thrown.getMessage());
    }

    // ------------------------------------------------------------------
    // Receipt
    // ------------------------------------------------------------------

    /**
     * The oversize string is a genuine receipt padded with spaces, which Apple's
     * {@code receipt-data} contract allows anywhere and {@code ReceiptBase64}
     * strips: without the bound this input VERIFIES, so the refusal can only
     * come from the bound.
     */
    @Test
    void receiptStringOverTheSizeLimitIsRefusedBeforeItIsDecoded() throws Exception {
        String receipt = paddedGenuineReceipt(ReceiptVerifier.MAX_RECEIPT_BYTES + 1);
        VerificationException thrown = assertThrows(
                VerificationException.class, () -> receiptVerifier().verify(receipt));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, thrown.reason());
        assertTrue(thrown.getMessage().contains("exceeds the maximum accepted size"), thrown.getMessage());
    }

    /** The same receipt one character shorter still verifies, so the bound is where it says it is. */
    @Test
    void receiptStringAtTheSizeLimitStillVerifies() throws Exception {
        String receipt = paddedGenuineReceipt(ReceiptVerifier.MAX_RECEIPT_BYTES);
        assertEquals(BUNDLE, receiptVerifier().verify(receipt).bundleId());
    }

    @Test
    void receiptDerOverTheSizeLimitIsRefusedBeforeItIsParsed() throws Exception {
        byte[] der = new byte[ReceiptVerifier.MAX_RECEIPT_BYTES + 1];
        VerificationException thrown = assertThrows(
                VerificationException.class, () -> receiptVerifier().verify(der));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, thrown.reason());
        assertTrue(thrown.getMessage().contains("exceeds the maximum accepted size"), thrown.getMessage());
    }

    /**
     * The static primitive is a public entry point of its own, so it carries
     * the same bound rather than relying on a verifier being in front of it.
     */
    @Test
    void verifyReceiptCoreCarriesTheSameBound() throws Exception {
        byte[] der = new byte[ReceiptVerifier.MAX_RECEIPT_BYTES + 1];
        VerificationException thrown = assertThrows(
                VerificationException.class,
                () -> ReceiptVerifier.verifyReceiptCore(der, Collections.singleton(receiptRoot())));
        assertTrue(thrown.getMessage().contains("exceeds the maximum accepted size"), thrown.getMessage());
    }

    /**
     * The normative floor in {@code fixtures/cases.json}: every port MUST
     * accept a well-formed receipt of up to 1 MiB of DER. Asserted here as
     * well as by the conformance suite, because that floor is what decides
     * whether {@link ReceiptVerifier#MAX_RECEIPT_BYTES} may ever be lowered.
     */
    @Test
    void theBoundClearsTheNormativeOneMebibyteReceiptFloor() {
        assertTrue(
                ReceiptVerifier.MAX_RECEIPT_BYTES >= 1048576 * 4 / 3,
                "the receipt bound must clear the base64 of a 1 MiB DER receipt");
    }

    // ------------------------------------------------------------------
    // verifyReceipt endpoint
    // ------------------------------------------------------------------

    /**
     * A request body over the limit carries a receipt that verifies, so
     * without the bound the answer is 0 rather than 21002.
     */
    @Test
    void requestBodyOverTheSizeLimitAnswers21002WithoutParsingIt() throws Exception {
        String body = requestJson(repeat('x', VerifyReceiptEndpoint.MAX_REQUEST_BYTES));
        assertTrue(body.length() > VerifyReceiptEndpoint.MAX_REQUEST_BYTES);
        assertEquals("{\"status\":21002}", endpoint().verifyReceiptJson(body));
    }

    /** And the same body with the padding removed is the verifying request it was built from. */
    @Test
    void theSameRequestBodyUnderTheLimitVerifies() throws Exception {
        String body = requestJson("");
        assertTrue(body.length() <= VerifyReceiptEndpoint.MAX_REQUEST_BYTES);
        assertTrue(endpoint().verifyReceiptJson(body).contains("\"status\":0"), "the unpadded request did not verify");
    }

    /** Nesting in the body is bounded for the same reason it is in a JWS header. */
    @Test
    void requestBodyNestedDeeperThanTheLimitAnswers21002() throws Exception {
        String body = requestJson(null).replace("}", ",\"deep\":" + nestedArray(200) + "}");
        assertEquals("{\"status\":21002}", endpoint().verifyReceiptJson(body));
    }

    /**
     * The {@code Map} entry point does not see the request body, so it applies
     * the receipt bound to {@code receipt-data} itself. Padded with spaces, so
     * without the bound the receipt verifies and the status is 0.
     */
    @Test
    void receiptDataOverTheReceiptLimitAnswers21002() throws Exception {
        Map<String, Object> request = new LinkedHashMap<String, Object>();
        request.put("receipt-data", paddedGenuineReceipt(ReceiptVerifier.MAX_RECEIPT_BYTES + 1));
        assertEquals(
                Integer.valueOf(VerifyReceiptEndpoint.STATUS_MALFORMED),
                endpoint().verifyReceipt(request).get("status"));
        assertNotEquals(
                Integer.valueOf(VerifyReceiptEndpoint.STATUS_OK),
                endpoint().verifyReceipt(request).get("status"));
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private static JwsVerifier jwsVerifier() throws Exception {
        return new JwsVerifier(Collections.singleton(root("jws-root.der")), BUNDLE, EnumSet.of(Environment.SANDBOX));
    }

    private static ReceiptVerifier receiptVerifier() throws Exception {
        return new ReceiptVerifier(Collections.singleton(receiptRoot()), BUNDLE);
    }

    private static VerifyReceiptEndpoint endpoint() throws Exception {
        return new VerifyReceiptEndpoint(Collections.singleton(receiptRoot()), Environment.SANDBOX);
    }

    private static X509Certificate receiptRoot() throws Exception {
        return root("receipt-root.der");
    }

    private static X509Certificate root(String name) throws Exception {
        byte[] der = Files.readAllBytes(FIXTURES.resolve(name));
        return (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    private static String genuineJws() throws Exception {
        return new String(Files.readAllBytes(FIXTURES.resolve("transaction.jws")), StandardCharsets.UTF_8).trim();
    }

    /** The genuine receipt as base64, space-padded to exactly {@code length} characters. */
    private static String paddedGenuineReceipt(int length) throws Exception {
        String base64 = Base64.getEncoder().encodeToString(Files.readAllBytes(FIXTURES.resolve("receipt.der")));
        return base64 + repeat(' ', length - base64.length());
    }

    /** A verifying request body, optionally carrying a padding field to grow it. */
    private static String requestJson(String padding) throws Exception {
        String base64 = Base64.getEncoder().encodeToString(Files.readAllBytes(FIXTURES.resolve("receipt.der")));
        String body = "{\"receipt-data\":\"" + base64 + "\"";
        if (padding != null && !padding.isEmpty()) {
            body = body + ",\"padding\":\"" + padding + "\"";
        }
        return body + "}";
    }

    /** A JWS whose header segment is the given JSON; the rest is the genuine one. */
    private static String headerJws(String headerJson) throws Exception {
        String[] parts = genuineJws().split("\\.");
        return Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)) + "."
                + parts[1] + "."
                + parts[2];
    }

    private static String nestedJson(int depth) {
        return "{\"deep\":" + nestedArray(depth) + "}";
    }

    private static String nestedArray(int depth) {
        StringBuilder json = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            json.append('[');
        }
        json.append('1');
        for (int i = 0; i < depth; i++) {
            json.append(']');
        }
        return json.toString();
    }

    /** Java 8 has no {@code String.repeat}, and the artifact's floor is 8. */
    private static String repeat(char c, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, c);
        return new String(chars);
    }
}
