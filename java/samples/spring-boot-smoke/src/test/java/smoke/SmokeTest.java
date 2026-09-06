package smoke;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.emindeniz99.applepurchasereceiptverifier.jws.AppTransactionPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.JwsVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.jws.TransactionPayload;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.AppReceipt;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.ReceiptVerifier;
import io.github.emindeniz99.applepurchasereceiptverifier.receipt.VerifyReceiptEndpoint;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * The point of these tests is the classpath they run on, not the verdicts:
 * Boot's BOM has replaced the library's own Jackson 2 pin and Jackson 3 sits
 * next to it. If either breaks the verifier, the context fails to start or a
 * verdict changes. Each public entry point gets one genuine input; the
 * shared conformance suite in ../../src/test covers the rest.
 */
@SpringBootTest
class SmokeTest {
    @Autowired JwsVerifier jws;
    @Autowired ReceiptVerifier receipts;
    @Autowired VerifyReceiptEndpoint endpoint;

    @Test
    void verifiesTheSharedTransactionFixture() throws Exception {
        TransactionPayload payload = jws.verifyTransaction(fixture("generated/transaction.jws"));
        assertThat(payload.bundleId()).isEqualTo("com.example.app");
        assertThat(payload.productId()).isEqualTo("com.example.app.pro");
    }

    @Test
    void verifiesTheSharedAppTransactionFixture() throws Exception {
        AppTransactionPayload payload = jws.verifyAppTransaction(fixture("generated/app-transaction.jws"));
        assertThat(payload.bundleId()).isEqualTo("com.example.app");
        assertThat(payload.appAppleId()).isEqualTo(123456789L);
    }

    /** A real sandbox receipt against the bundled Apple roots, so the anchors are proven to load here. */
    @Test
    void verifiesAGenuineLegacyReceiptAgainstTheBundledAppleRoots() throws Exception {
        AppReceipt receipt = receipts.verify(fixture("public-receipts/receipt-sandbox-g5.b64"));
        assertThat(receipt.bundleId()).isEqualTo("dev.bonzer.weeka.app");
        assertThat(receipt.receiptType()).isEqualTo("ProductionSandbox");
        assertThat(receipt.inAppPurchases()).hasSize(2);
    }

    @Test
    void answersTheVerifyReceiptShimForAGenuineReceipt() throws Exception {
        Map<String, Object> response = endpoint.verifyReceipt(
                Collections.singletonMap("receipt-data", fixture("public-receipts/receipt-sandbox-g5.b64")));
        assertThat(response.get("status")).isEqualTo(0);
        assertThat(response.get("environment")).isEqualTo("Sandbox");
    }

    /** Both Jackson majors are loadable at once; the library keeps using Jackson 2. */
    @Test
    void jackson2AndJackson3Coexist() {
        assertThat(com.fasterxml.jackson.databind.ObjectMapper.class.getPackage().getImplementationVersion())
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
