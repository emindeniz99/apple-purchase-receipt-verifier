import java.io.*; import java.net.*;
public class H { public static void main(String[] a) throws Exception {
  ProcessBuilder pb = new ProcessBuilder(a[0], "Sandbox"); pb.redirectErrorStream(false);
  Process p = pb.start(); BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line; int port = -1; while ((line = r.readLine()) != null) { if (line.startsWith("APRV_SIDECAR_PORT=")) { port = Integer.parseInt(line.substring(18)); break; } }
  URL u = new URL("http://127.0.0.1:" + port + "/health");
  for (int i = 0; i < 3000; i++) get(u);
  long t = System.nanoTime(); int n = 20000; for (int i = 0; i < n; i++) get(u);
  System.out.println("HTTP round trip only (GET /health, HttpURLConnection keep-alive): " + (System.nanoTime() - t) / n / 1000 + " us/op");
  p.getOutputStream().close(); p.destroy();
}
static void get(URL u) throws Exception { HttpURLConnection c = (HttpURLConnection) u.openConnection(); InputStream in = c.getInputStream(); byte[] b = new byte[256]; while (in.read(b) > 0) {} in.close(); } }
