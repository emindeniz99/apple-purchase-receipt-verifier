import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Does a ProxySelector that answers SOCKS for socket:// URIs carry a
 * connection that HttpURLConnection opened with Proxy.NO_PROXY? Prints,
 * for http and https, how many connections reached the "SOCKS proxy" (a
 * listener that accepts and closes), and the same for a plain new Socket(),
 * the way the hand-written client connected.
 */
public class SocksProbe {
    public static void main(String[] args) throws Exception {
        final ServerSocket socks = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        final AtomicInteger reached = new AtomicInteger();
        Thread t = new Thread(() -> {
            while (true) {
                try (Socket s = socks.accept()) {
                    reached.incrementAndGet();
                } catch (IOException e) {
                    return;
                }
            }
        });
        t.setDaemon(true);
        t.start();
        final Proxy proxy = new Proxy(Proxy.Type.SOCKS, socks.getLocalSocketAddress());
        ProxySelector.setDefault(new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                return Collections.singletonList(uri.getScheme().equals("socket") ? proxy : Proxy.NO_PROXY);
            }

            @Override
            public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {}
        });
        int target;
        try (ServerSocket closed = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            target = closed.getLocalPort();
        }
        System.out.println("java.version=" + System.getProperty("java.version"));
        for (String scheme : new String[] {"http", "https"}) {
            int before = reached.get();
            HttpURLConnection c = (HttpURLConnection)
                    new URL(scheme, "127.0.0.1", target, "/healthz").openConnection(Proxy.NO_PROXY);
            c.setConnectTimeout(2000);
            c.setReadTimeout(2000);
            String outcome;
            try {
                outcome = "status " + c.getResponseCode();
            } catch (IOException e) {
                outcome = e.getClass().getSimpleName();
            }
            Thread.sleep(200);
            System.out.println("HttpURLConnection(NO_PROXY) " + scheme + ": reached SOCKS listener "
                    + (reached.get() - before) + " time(s), " + outcome);
        }
        int before = reached.get();
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress("127.0.0.1", target), 2000);
        } catch (IOException e) {
            // expected
        }
        Thread.sleep(200);
        System.out.println("new Socket() (hand-written client): reached SOCKS listener " + (reached.get() - before)
                + " time(s)");
    }
}
