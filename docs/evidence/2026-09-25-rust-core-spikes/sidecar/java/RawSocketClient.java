import java.io.*; import java.net.*; import java.nio.file.*;
/** Java 8 keep-alive HTTP/1.1 client: one write per request, TCP_NODELAY. */
public class RawSocketClient { public static void main(String[] a) throws Exception {
  Process p = new ProcessBuilder(a[0], "Sandbox").start(); BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line; int port = -1; while ((line = r.readLine()) != null) { if (line.startsWith("APRV_SIDECAR_PORT=")) { port = Integer.parseInt(line.substring(18)); break; } }
  Socket s = new Socket("127.0.0.1", port); s.setTcpNoDelay(true);
  OutputStream out = new BufferedOutputStream(s.getOutputStream(), 16384); DataInputStream in = new DataInputStream(new BufferedInputStream(s.getInputStream(), 16384));
  String b64 = new String(Files.readAllBytes(Paths.get("$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64")), "US-ASCII").replaceAll("\\s", "");
  for (String[] c : new String[][]{{"tiny body", "not json"}, {"full receipt (status 0)", "{\"receipt-data\":\"" + b64 + "\"}"}}) {
    byte[] body = c[1].getBytes("UTF-8"); String resp = null;
    for (int i = 0; i < 2000; i++) resp = post(out, in, body);
    long t = System.nanoTime(); int n = 10000; for (int i = 0; i < n; i++) resp = post(out, in, body);
    System.out.println("raw-socket POST " + c[0] + ": " + (System.nanoTime() - t) / n / 1000 + " us/op  -> " + resp.substring(0, Math.min(40, resp.length())));
  }
  s.close(); p.getOutputStream().close(); p.destroy();
}
static String post(OutputStream out, DataInputStream in, byte[] body) throws IOException {
  out.write(("POST /verifyReceipt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: " + body.length + "\r\n\r\n").getBytes("US-ASCII"));
  out.write(body); out.flush();
  int len = -1; String h;
  while (!(h = readLine(in)).isEmpty()) { if (h.toLowerCase().startsWith("content-length:")) len = Integer.parseInt(h.substring(15).trim()); }
  byte[] b = new byte[len]; in.readFully(b); return new String(b, "UTF-8");
}
static String readLine(DataInputStream in) throws IOException { StringBuilder sb = new StringBuilder(); int ch; while ((ch = in.read()) != '\n') { if (ch != '\r') sb.append((char) ch); } return sb.toString(); } }
