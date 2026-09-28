package smoke;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.emindeniz99.applepurchasereceiptverifier.Environment;
import io.github.emindeniz99.applepurchasereceiptverifier.JsonPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.ReceiptPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.VerificationResult;
import io.github.emindeniz99.applepurchasereceiptverifier.Verifier;
import java.io.IOException;
import java.nio.file.Files;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * The point of these tests is the classpath they run on, not the verdicts:
 * Boot's BOM has replaced the library's own Jackson 2 pin and Jackson 3 sits
 * next to it. If either breaks the verifier, the context fails to start or a
 * verdict changes. Each public method gets one genuine input; the shared
 * conformance suite in ../../src/test covers the rest.
 */
@SpringBootTest
class SmokeTest {
    @Autowired Verifier verifier;

    @Test
    void verifiesTheSharedTransactionFixture() throws Exception {
        VerificationResult<JsonPayload> result = verifier.verifySignedData(fixture("generated/transaction.jws"));
        assertThat(result.verified()).as(String.valueOf(result.failure())).isTrue();
        assertThat(result.payload().json()).contains("\"bundleId\":\"com.example.app\"");
        assertThat(result.payload().json()).contains("\"productId\":\"com.example.app.pro\"");
    }

    @Test
    void verifiesTheSharedAppTransactionFixture() throws Exception {
        VerificationResult<JsonPayload> result = verifier.verifySignedData(fixture("generated/app-transaction.jws"));
        assertThat(result.verified()).as(String.valueOf(result.failure())).isTrue();
        assertThat(result.payload().json()).contains("\"appAppleId\":123456789");
    }

    /** A real sandbox receipt against the bundled Apple roots, so the anchors are proven to load here. */
    @Test
    void verifiesAGenuineLegacyReceiptAgainstTheBundledAppleRoots() throws Exception {
        VerificationResult<ReceiptPayload> result =
                verifier.verifyReceipt(fixture("public-receipts/receipt-sandbox-g5.b64"));
        assertThat(result.verified()).as(String.valueOf(result.failure())).isTrue();
        assertThat(result.payload().bundleId()).isEqualTo("dev.bonzer.weeka.app");
        assertThat(result.payload().receiptType()).isEqualTo("ProductionSandbox");
        assertThat(result.payload().inApp()).hasSize(2);
    }

    @Test
    void answersTheVerifyReceiptShimForAGenuineReceipt() throws Exception {
        String response = verifier.verifyReceiptEndpoint(
                Environment.SANDBOX,
                "{\"receipt-data\":\"" + fixture("public-receipts/receipt-sandbox-g5.b64") + "\"}");
        assertThat(response).startsWith("{\"status\":0,\"environment\":\"Sandbox\",");
    }

    /** Both Jackson majors are loadable at once; the library keeps using Jackson 2's jackson-core. */
    @Test
    void jackson2AndJackson3Coexist() {
        assertThat(com.fasterxml.jackson.core.JsonFactory.class.getPackage().getImplementationVersion())
                .as("Jackson 2 version pinned by the Spring Boot BOM")
                .startsWith("2.");
        assertThat(tools.jackson.databind.ObjectMapper.class.getPackage().getImplementationVersion())
                .as("Jackson 3 version pinned by the Spring Boot BOM")
                .startsWith("3.");
    }

    private static String fixture(String path) throws IOException {
        return Files.readString(Fixtures.dir().resolve(path)).trim();
    }
}
