package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Throwaway probe for docs/evidence/2026-10-02-java-httpurlconnection.md:
 * how many times can one ServerConnection.send put a POST on the wire when
 * the server keeps failing? Copy into
 * java-wasm/src/test/java/io/github/emindeniz99/applepurchasereceiptverifier/.
 *
 * The server cycles through three behaviours, one per connection: reset
 * at once without reading, so a 4 MiB body cannot be written and
 * HttpURLConnection sees a write error; read the whole request and close
 * before a status line; reset again. Prints the connections and the whole
 * requests the server saw for one send() of three attempts.
 */
class ResendProbe {

    @Test
    void probe() throws Exception {
        AtomicInteger connections = new AtomicInteger();
        AtomicInteger whole = new AtomicInteger();
        try (ServerSocket server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Thread thread = new Thread(() -> {
                while (true) {
                    try (Socket client = server.accept()) {
                        if (connections.incrementAndGet() % 3 != 2) {
                            client.setSoLinger(true, 0); // close with a reset
                        } else if (readRequest(client.getInputStream())) {
                            whole.incrementAndGet();
                        }
                    } catch (IOException e) {
                        if (server.isClosed()) {
                            return;
                        }
                    }
                }
            });
            thread.setDaemon(true);
            thread.start();
            ServerConnection connection = ServerConnection.fixed(
                    new ServerConnection.Target("127.0.0.1", server.getLocalPort(), false, "", null, 0), "probe");
            assertThrows(ServerProcessFailure.class, () -> connection.send("POST", "/v1/x", new byte[4 << 20], 0L));
            Thread.sleep(500);
            System.out.println("PROBE java " + System.getProperty("java.version") + ": " + connections.get()
                    + " connections, " + whole.get() + " whole requests read");
        }
    }

    /** Reads the head and a Content-Length body; true when the whole request arrived. */
    private static boolean readRequest(InputStream in) throws IOException {
        StringBuilder head = new StringBuilder();
        while (head.length() < 4 || !head.substring(head.length() - 4).equals("\r\n\r\n")) {
            int c = in.read();
            if (c < 0) {
                return false;
            }
            head.append((char) c);
        }
        long length = 0;
        for (String line : head.toString().split("\r\n")) {
            if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                length = Long.parseLong(line.substring(15).trim());
            }
        }
        byte[] buffer = new byte[64 << 10];
        while (length > 0) {
            int n = in.read(buffer, 0, (int) Math.min(buffer.length, length));
            if (n < 0) {
                return false;
            }
            length -= n;
        }
        return true;
    }
}
