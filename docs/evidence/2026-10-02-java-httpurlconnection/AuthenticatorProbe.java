import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Does HttpURLConnection answer a 401 with a Basic challenge using the
 * JVM's default Authenticator, and what stops it? A server answers every
 * request with 401 and "WWW-Authenticate: Basic"; a default Authenticator
 * that hands out credentials is installed. One buffered POST per mode,
 * printing the status, how many connections the server took and how many
 * of them carried "Authorization: Basic":
 *
 * - plain: the request as the engine sent it before the fix;
 * - bearer: the same with an "Authorization: Bearer" header set by the
 *   caller (the JDK's isUserServerAuth flag);
 * - perConnection: HttpURLConnection.setAuthenticator (Java 9 and later)
 *   with an Authenticator that has no credentials, called reflectively as
 *   the engine does.
 *
 * Compile with Java 8 and run on each JDK.
 */
public class AuthenticatorProbe {
    static final AtomicInteger connections = new AtomicInteger();
    static final AtomicInteger basic = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        final ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        Thread t = new Thread(() -> {
            while (true) {
                try (Socket c = server.accept()) {
                    connections.incrementAndGet();
                    BufferedReader in = new BufferedReader(
                            new InputStreamReader(c.getInputStream(), StandardCharsets.ISO_8859_1));
                    String line;
                    int length = 0;
                    while ((line = in.readLine()) != null && !line.isEmpty()) {
                        String lower = line.toLowerCase(Locale.ROOT);
                        if (lower.startsWith("authorization: basic")) {
                            basic.incrementAndGet();
                        }
                        if (lower.startsWith("content-length:")) {
                            length = Integer.parseInt(line.substring(15).trim());
                        }
                    }
                    for (int i = 0; i < length; i++) {
                        in.read();
                    }
                    String body = "{\"code\":\"UNAUTHORIZED\"}";
                    c.getOutputStream()
                            .write(("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"r\"\r\n"
                                            + "Content-Length: " + body.length() + "\r\nConnection: close\r\n\r\n" + body)
                                    .getBytes(StandardCharsets.ISO_8859_1));
                } catch (IOException e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
        Authenticator.setDefault(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication("app-user", "app-password".toCharArray());
            }
        });
        System.out.println("PROBE java " + System.getProperty("java.version"));
        for (String mode : new String[] {"plain", "bearer", "perConnection"}) {
            connections.set(0);
            basic.set(0);
            String result;
            try {
                HttpURLConnection http = (HttpURLConnection)
                        new URL("http://127.0.0.1:" + server.getLocalPort() + "/v1/x").openConnection(Proxy.NO_PROXY);
                http.setRequestMethod("POST");
                http.setDoOutput(true);
                http.setUseCaches(false);
                http.setInstanceFollowRedirects(false);
                http.setRequestProperty("X-Aprv-Token", "token");
                if (mode.equals("bearer")) {
                    http.setRequestProperty("Authorization", "Bearer token");
                }
                if (mode.equals("perConnection")) {
                    try {
                        HttpURLConnection.class
                                .getMethod("setAuthenticator", Authenticator.class)
                                .invoke(http, new Authenticator() {});
                    } catch (NoSuchMethodException e) {
                        System.out.println("PROBE " + mode + ": no HttpURLConnection.setAuthenticator");
                        continue;
                    }
                }
                try (OutputStream out = http.getOutputStream()) {
                    out.write(new byte[] {1, 2, 3});
                }
                int status = http.getResponseCode();
                InputStream error = http.getErrorStream();
                result = "status " + status + ", body "
                        + (error == null ? "none" : new String(readAll(error), StandardCharsets.UTF_8));
            } catch (IOException e) {
                result = e.toString();
            }
            Thread.sleep(200);
            System.out.println("PROBE " + mode + ": " + result + ", connections " + connections.get()
                    + ", with Authorization: Basic " + basic.get());
        }
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int n;
        while ((n = in.read(buffer)) >= 0) {
            bytes.write(buffer, 0, n);
        }
        return bytes.toByteArray();
    }
}
