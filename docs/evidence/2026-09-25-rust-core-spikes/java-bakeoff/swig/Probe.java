import bakeoff.swig.raw.*;
import java.nio.file.*;

public class Probe {
  public static void main(String[] a) throws Exception {
    System.loadLibrary("aprv");
    System.out.println("version: " + aprv.aprv_version());

    String b64 = new String(Files.readAllBytes(Paths.get(
        "$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64")))
        .replaceAll("\\s", "");

    SWIGTYPE_p_AprvReceiptVerifier v = aprv.receipt_new("dev.bonzer.weeka.app", null);
    int[] st = new int[1];
    String json = aprv.receipt_verify_base64(v, b64, st);
    System.out.println("FULL:" + json);

    // wrong bundle id -> WRONG_BUNDLE_ID (6)
    SWIGTYPE_p_AprvReceiptVerifier v2 = aprv.receipt_new("x.y", null);
    String json2 = aprv.receipt_verify_base64(v2, b64, st);
    System.out.println("wrong-bundle status=" + st[0] + " json=" + json2);

    // bad config -> exception
    try {
      aprv.receipt_new("", null);
      System.out.println("NO EXCEPTION (bad)");
    } catch (IllegalArgumentException e) {
      System.out.println("config exception ok: " + e.getMessage());
    }

    // JWS
    String jws = new String(Files.readAllBytes(Paths.get(
        "$REPO/fixtures/generated/transaction.jws"))).trim();
    byte[] jwsRoot = Files.readAllBytes(Paths.get("$REPO/fixtures/generated/jws-root.der"));
    SWIGTYPE_p_AprvJwsVerifier jv = aprv.jws_new("com.example.app", 2L /*SANDBOX*/, java.math.BigInteger.ZERO, new byte[][]{jwsRoot});
    String jjson = aprv.jws_verify_transaction(jv, jws, st);
    System.out.println("jws status=" + st[0] + " json=" + jjson);

    // endpoint
    SWIGTYPE_p_AprvReceiptEndpoint ep = aprv.endpoint_new(1L /*PRODUCTION*/, null);
    int[] rc = new int[1];
    String body = "{\"receipt-data\":\"" + b64 + "\"}";
    String resp = aprv.endpoint_verify_json(ep, body, rc);
    System.out.println("ENDPOINTFULL:" + resp);
    String resp2 = aprv.endpoint_verify_json(ep, "not json", rc);
    System.out.println("ENDPOINTBAD:" + resp2 + " rc=" + rc[0]);

    SWIGTYPE_p_AprvReceiptEndpoint epS = aprv.endpoint_new(2L /*SANDBOX*/, null);
    String respS = aprv.endpoint_verify_json(epS, body, rc);
    System.out.println("ENDPOINTSANDBOX:" + respS);

    // roots array smoke test
    byte[] root = Files.readAllBytes(Paths.get("$REPO/fixtures/generated/receipt-root.der"));
    SWIGTYPE_p_AprvReceiptVerifier v3 = aprv.receipt_new("com.example.app", new byte[][]{root});
    byte[] der = Files.readAllBytes(Paths.get("$REPO/fixtures/generated/receipt.der"));
    String j3 = aprv.receipt_verify_der(v3, der, st);
    System.out.println("custom-root status=" + st[0] + " json[0..80]=" + j3.substring(0, Math.min(80, j3.length())));

    System.out.println("ALL PROBES RAN");
  }
}
