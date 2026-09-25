package aprvj.web;

import aprvj.Bridge;

/**
 * Web Image (native-image --tool:svm-wasm) probe: the same Bridge calls as
 * the C ABI, driven from main because Web Image builds an application, not
 * a library. Inputs come as arguments so the probe needs no file system.
 *
 *   node web/wasm-main.js <receipt base64> <transaction.jws> <jws-root.der as base64> <iterations>
 */
public final class WebMain {

    public static void main(String[] args) throws Exception {
        String receipt = args[0];
        String jws = args[1];
        String root = args[2];
        int iterations = Integer.parseInt(args[3]);

        long t0 = System.nanoTime();
        Object rv = Bridge.newReceiptVerifier("{\"bundleId\":\"dev.bonzer.weeka.app\"}");
        Object jv = Bridge.newJwsVerifier("{\"bundleId\":\"com.example.app\",\"acceptedEnvironments\":[\"Sandbox\"],\"roots\":[\""
                + root + "\"]}");
        Object ep = Bridge.newEndpoint("{\"environment\":\"Sandbox\",\"nowMillis\":1767225600000}");
        long t1 = System.nanoTime();
        System.out.println("constructors ms " + (t1 - t0) / 1e6);
        System.out.println("self_check " + Bridge.selfCheck().code + " " + Bridge.selfCheck().json);

        Bridge.Result r = Bridge.verifyReceipt(rv, receipt.getBytes("US-ASCII"), true, null);
        System.out.println("receipt " + r.code + " " + r.json.substring(0, Math.min(120, r.json.length())));
        Bridge.Result j = Bridge.verifyJws(jv, jws, Bridge.JWS_TRANSACTION);
        System.out.println("jws " + j.code + " " + j.json.substring(0, Math.min(120, j.json.length())));
        Bridge.Result e = Bridge.verifyReceiptJson(ep, "{\"receipt-data\":\"" + receipt + "\"}");
        System.out.println("endpoint " + e.code + " " + e.json.substring(0, Math.min(80, e.json.length())));
        Bridge.Result wrong = Bridge.verifyReceipt(
                Bridge.newReceiptVerifier("{\"bundleId\":\"com.other\"}"), receipt.getBytes("US-ASCII"), true, null);
        System.out.println("wrong bundle " + wrong.code);

        for (String op : new String[] {"receipt", "jws"}) {
            long a = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                Bridge.Result x = op.equals("receipt")
                        ? Bridge.verifyReceipt(rv, receipt.getBytes("US-ASCII"), true, null)
                        : Bridge.verifyJws(jv, jws, Bridge.JWS_TRANSACTION);
                if (x.code != 0) {
                    throw new IllegalStateException(op + " " + x.json);
                }
            }
            System.out.println(op + " mean us " + (System.nanoTime() - a) / 1e3 / iterations + " over " + iterations);
        }
    }

    private WebMain() {}
}
