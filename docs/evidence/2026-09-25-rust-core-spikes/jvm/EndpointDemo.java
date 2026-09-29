package spike;

import java.nio.file.Files;
import java.nio.file.Paths;
import uniffi.aprv_uniffi.Environment;
import uniffi.aprv_uniffi.VerifyReceiptEndpoint;
import uniffi.aprv_uniffi.VerifyReceiptResult;

public final class EndpointDemo {
    public static void main(String[] args) throws Exception {
        String b64 = new String(Files.readAllBytes(Paths.get("../../../../fixtures/public-receipts/receipt-sandbox-g5.b64")), "US-ASCII")
                .replaceAll("\\s", "");
        String body = "{\"receipt-data\":\"" + b64 + "\",\"exclude-old-transactions\":false}";
        System.out.println("java.version=" + System.getProperty("java.version"));

        try (VerifyReceiptEndpoint production = new VerifyReceiptEndpoint(Environment.PRODUCTION, null);
             VerifyReceiptEndpoint sandbox = new VerifyReceiptEndpoint(Environment.SANDBOX, null)) {

            // 1. The drop-in: raw JSON in, raw JSON out (sandbox receipt sent to production)
            String response = production.verifyReceiptJson(body);
            System.out.println("production endpoint -> " + response.substring(0, Math.min(90, response.length())) + "...");

            // 2. Result object: status + typed receipt, then re-render for sandbox without verifying twice
            try (VerifyReceiptResult r = production.verifyReceiptResult(body)) {
                System.out.println("status=" + r.status() + " verified=" + r.verified()
                        + " bundleId=" + r.receipt().getBundleId());
                String asSandbox = r.toJsonIn(Environment.SANDBOX);
                System.out.println("re-rendered for sandbox -> " + asSandbox.substring(0, 60) + "...");
            }

            // 3. Sandbox endpoint answers 0 directly
            System.out.println("sandbox endpoint -> status " + sandbox.verifyReceiptResult(body).status());

            // 4. Garbage in: no exception, just Apple's 21002
            try (VerifyReceiptResult bad = sandbox.verifyReceiptResult("not json")) {
                System.out.println("bad body -> status " + bad.status() + " reason " + bad.failureReason()
                        + " json " + bad.toJson());
            }
        }
    }
}
