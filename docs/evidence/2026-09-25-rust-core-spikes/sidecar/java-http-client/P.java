import java.io.*; import java.net.*; import java.nio.file.*;
public class P { public static void main(String[] a) throws Exception {
  Process p = new ProcessBuilder(a[0], "Sandbox").start(); BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line; int port = -1; while ((line = r.readLine()) != null) { if (line.startsWith("APRV_SIDECAR_PORT=")) { port = Integer.parseInt(line.substring(18)); break; } }
  URL u = new URL("http://127.0.0.1:" + port + "/verifyReceipt");
  String b64 = new String(Files.readAllBytes(Paths.get("$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
  for (String[] c : new String[][]{{"tiny body (not json -> 21002)", "not json"}, {"full receipt (status 0)", "{\"receipt-data\":\"" + b64 + "\"}"}}) {
    byte[] body = c[1].getBytes("UTF-8");
    for (int i = 0; i < 2000; i++) post(u, body);
    long t = System.nanoTime(); int n = 5000; for (int i = 0; i < n; i++) post(u, body);
    System.out.println("POST " + c[0] + ": " + (System.nanoTime() - t) / n / 1000 + " us/op (" + body.length + " B body)");
  }
  p.getOutputStream().close(); p.destroy();
}
static void post(URL u, byte[] body) throws Exception {
  HttpURLConnection c = (HttpURLConnection) u.openConnection(); c.setDoOutput(true); c.setRequestMethod("POST");
  c.setRequestProperty("Content-Type", "application/json"); c.setFixedLengthStreamingMode(body.length);
  OutputStream o = c.getOutputStream(); o.write(body); o.close();
  InputStream in = c.getInputStream(); byte[] b = new byte[8192]; while (in.read(b) > 0) {} in.close(); } }
