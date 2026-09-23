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
     * The oversize string is a genuine receipt padded with spaces. The strict
     * decoder would refuse the spaces too, so the verdict alone cannot show
     * which check fired; the message can, and it names the size bound, which
     * runs before anything is decoded.
     */
    @Test
    void receiptStringOverTheSizeLimitIsRefusedBeforeItIsDecoded() throws Exception {
        String receipt = paddedGenuineReceipt(ReceiptVerifier.MAX_RECEIPT_BYTES + 1);
        VerificationException thrown = assertThrows(
                VerificationException.class, () -> receiptVerifier().verify(receipt));
        assertEquals(Reason.INVALID_RECEIPT_FORMAT, thrown.reason());
        assertTrue(thrown.getMessage().contains("exceeds the maximum accepted size"), thrown.getMessage());
    }

    /**
     * A string exactly at the bound still verifies, so the bound is where it
     * says it is. Canonical base64 admits nothing around the data, so the
     * string is a genuinely signed receipt whose base64 is exactly the bound
     * (fixtures/limits/receipt-b64-at-cap.txt, from ReceiptBase64CapFixture).
     */
    @Test
    void receiptStringAtTheSizeLimitStillVerifies() throws Exception {
        String receipt = new String(
                Files.readAllBytes(Paths.get("..", "fixtures", "limits", "receipt-b64-at-cap.txt")),
                StandardCharsets.US_ASCII);
        assertEquals(ReceiptVerifier.MAX_RECEIPT_BYTES, receipt.length());
        ReceiptVerifier verifier = new ReceiptVerifier(Collections.singleton(root("receipt-b64-cap-root.der")), BUNDLE);
        assertEquals(BUNDLE, verifier.verify(receipt).bundleId());
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
     * The limits are Apple's, fixed in every port by fixtures/cases.json:
     * Apple's verifyReceipt answers a 3,145,728-byte request body and refuses
     * a 3,145,729-byte one (measured 2026-09-23), and no receipt it accepts
     * can be larger than the body that carries it.
     */
    @Test
    void theBoundsAreApplesThreeMebibytes() {
        assertEquals(3145728, VerifyReceiptEndpoint.MAX_REQUEST_BYTES);
        assertEquals(3145728, ReceiptVerifier.MAX_RECEIPT_BYTES);
    }

    // ------------------------------------------------------------------
    // verifyReceipt endpoint
    // ------------------------------------------------------------------

    /**
     * A request body over the limit carries a receipt that verifies, so
     * without the bound the answer is 0 rather than 21002. The reason is
     * REQUEST_TOO_LARGE, the one an HTTP layer maps to 413 as Apple does.
     */
    @Test
    void requestBodyOverTheSizeLimitAnswers21002WithoutParsingIt() throws Exception {
        String body = requestJson(repeat('x', VerifyReceiptEndpoint.MAX_REQUEST_BYTES));
        assertTrue(body.length() > VerifyReceiptEndpoint.MAX_REQUEST_BYTES);
        assertEquals("{\"status\":21002}", endpoint().verifyReceiptJson(body));
        assertEquals(
                Reason.REQUEST_TOO_LARGE, endpoint().verifyReceiptResult(body).failureReason());
    }

    /**
     * Apple's limit counts UTF-8 bytes. A body padded with U+00E9 to one byte
     * over the limit is barely half the limit in characters, so a character
     * count lets it through; the same shape one byte shorter verifies.
     */
    @Test
    void requestBodyIsMeasuredInUtf8BytesNotCharacters() throws Exception {
        int limit = VerifyReceiptEndpoint.MAX_REQUEST_BYTES;
        int fixed = requestJson(null).length() + ",\"padding\":\"\"".length();

        String overBody = requestJson(twoBytePadding(limit + 1 - fixed));
        assertEquals(limit + 1, overBody.getBytes(StandardCharsets.UTF_8).length);
        assertTrue(overBody.length() < limit / 2 + fixed, "a character count calls this one far under the limit");
        assertEquals(
                Reason.REQUEST_TOO_LARGE,
                endpoint().verifyReceiptResult(overBody).failureReason());

        String atBody = requestJson(twoBytePadding(limit - fixed));
        assertEquals(limit, atBody.getBytes(StandardCharsets.UTF_8).length);
        assertEquals(
                VerifyReceiptEndpoint.STATUS_OK,
                endpoint().verifyReceiptResult(atBody).status());
    }

    /** Nesting in the body is bounded for the same reason it is in a JWS header. */
    @Test
    void requestBodyNestedDeeperThanTheLimitAnswers21002() throws Exception {
        String body = requestJson(null).replace("}", ",\"deep\":" + nestedArray(200) + "}");
        assertEquals("{\"status\":21002}", endpoint().verifyReceiptJson(body));
    }

    /**
     * The {@code Map} entry point does not see the request body, so it applies
     * the receipt bound to {@code receipt-data} itself. No string over the
     * bound is valid receipt-data, so without the bound this would be 21002
     * too; what it pins is that the endpoint's answer stays 21002 with
     * INVALID_RECEIPT_FORMAT rather than anything the decode could throw.
     */
    @Test
    void receiptDataOverTheReceiptLimitAnswers21002() throws Exception {
        Map<String, Object> request = new LinkedHashMap<String, Object>();
        request.put("receipt-data", paddedGenuineReceipt(ReceiptVerifier.MAX_RECEIPT_BYTES + 1));
        assertEquals(
                Integer.valueOf(VerifyReceiptEndpoint.STATUS_MALFORMED),
                endpoint().verifyReceiptResult(request).toResponse().get("status"));
        assertNotEquals(
                Integer.valueOf(VerifyReceiptEndpoint.STATUS_OK),
                endpoint().verifyReceiptResult(request).toResponse().get("status"));
        assertEquals(
                Reason.INVALID_RECEIPT_FORMAT,
                endpoint().verifyReceiptResult(request).failureReason());
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

    /** Exactly {@code bytes} UTF-8 bytes of U+00E9, with one ASCII character when the count is odd. */
    private static String twoBytePadding(int bytes) {
        return repeat('\u00e9', bytes / 2) + (bytes % 2 == 1 ? "a" : "");
    }

    /** Java 8 has no {@code String.repeat}, and the artifact's floor is 8. */
    private static String repeat(char c, int count) {
        char[] chars = new char[count];
        Arrays.fill(chars, c);
        return new String(chars);
    }
}
