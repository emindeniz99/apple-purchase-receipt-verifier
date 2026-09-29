import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Demo per the research spike: genuine sandbox receipt against a Production
 * sidecar (expect 21007), against a Sandbox sidecar (expect status 0), and
 * "not json" against a Sandbox sidecar (expect 21002).
 *
 * <p>Prints PASS/FAIL per check and exits non-zero if anything failed.
 */
public final class Demo {

    public static void main(String[] args) throws Exception {
        String fixturesDir = System.getProperty(
                "aprv.demo.fixtures", "$REPO/fixtures");
        String receiptPath = fixturesDir + "/public-receipts/receipt-sandbox-g5.b64";
        String b64 = new String(Files.readAllBytes(Paths.get(receiptPath)), StandardCharsets.UTF_8)
                .replaceAll("\\s+", "");
        String receiptBody = "{\"receipt-data\":\"" + b64 + "\"}";

        boolean allPass = true;
        allPass &= check("Production sidecar + genuine sandbox receipt -> 21007",
                "Production", receiptBody, 21007);
        allPass &= check("Sandbox sidecar + genuine sandbox receipt -> 0",
                "Sandbox", receiptBody, 0);
        allPass &= check("Sandbox sidecar + \"not json\" -> 21002",
                "Sandbox", "not json", 21002);

        System.out.println();
        System.out.println(allPass ? "ALL DEMOS PASSED" : "SOME DEMOS FAILED");
        System.exit(allPass ? 0 : 1);
    }

    private static boolean check(String label, String environment, String body, int expectedStatus)
            throws IOException {
        try (SidecarVerifier sidecar = new SidecarVerifier(environment)) {
            String response = sidecar.verifyReceiptJson(body);
            int actual = extractStatus(response);
            boolean pass = actual == expectedStatus;
            System.out.println((pass ? "PASS" : "FAIL") + "  " + label
                    + "  [expected status=" + expectedStatus + ", got status=" + actual + "]");
            if (!pass) {
                System.out.println("      response: " + response);
            }
            return pass;
        }
    }

    /** Pulls the top-level {@code "status":<int>} out of the response without a JSON library. */
    private static int extractStatus(String json) {
        int idx = json.indexOf("\"status\":");
        if (idx < 0) {
            throw new IllegalStateException("no \"status\" field in response: " + json);
        }
        int start = idx + "\"status\":".length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        return Integer.parseInt(json.substring(start, end));
    }
}
