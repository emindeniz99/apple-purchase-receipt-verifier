public class T { public static void main(String[] a) throws Exception {
  System.loadLibrary("aprv");
  String b = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("../../../../../fixtures/public-receipts/receipt-sandbox-g5.b64"))).replaceAll("\\s","");
  System.out.println("java: " + aprv.aprv.verify_receipt_base64(aprv.aprv.aprv_verifier_new_receipt("dev.bonzer.weeka.app"), b).substring(0,40));
  try { aprv.aprv.verify_receipt_base64(aprv.aprv.aprv_verifier_new_receipt("x.y"), b); } catch (IllegalArgumentException e) { System.out.println("java error ok: " + e.getMessage()); }
}}
