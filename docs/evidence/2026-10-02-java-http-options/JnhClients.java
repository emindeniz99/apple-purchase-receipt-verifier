package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import javax.net.ssl.SSLContext;

/**
 * java.net.http.HttpClient (Java 11+). {@link #hardened()}: HTTP/1.1 only
 * (no h2c upgrade), no proxy, no redirects, no Authenticator, its own
 * SSLContext (not SSLContext.getDefault()), a request timeout, and the same
 * two checks as the HttpClient 5 adapter (framed bodies only, cap refused).
 * {@link #defaults()} is HttpClient.newHttpClient(). A new client per call,
 * so no connection is reused between scenarios.
 */
public final class JnhClients {

    public static ClientMatrix.Client hardened() {
        return new Jnh("jnh-hardened", true);
    }

    public static ClientMatrix.Client defaults() {
        return new Jnh("jnh-default", false);
    }

    static final class Jnh implements ClientMatrix.Client {
        private final String name;
        private final boolean hardened;

        Jnh(String name, boolean hardened) {
            this.name = name;
            this.hardened = hardened;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public ClientMatrix.Answer post(String scheme, String host, int port, byte[] body) throws Exception {
            HttpClient client;
            if (hardened) {
                SSLContext tls = SSLContext.getInstance("TLS");
                tls.init(null, null, null);
                client = HttpClient.newBuilder()
                        .version(HttpClient.Version.HTTP_1_1)
                        .proxy(HttpClient.Builder.NO_PROXY)
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .connectTimeout(Duration.ofSeconds(5))
                        .sslContext(tls)
                        .build();
            } else {
                client = HttpClient.newHttpClient();
            }
            HttpRequest request = HttpRequest.newBuilder(URI.create(scheme + "://" + host + ":" + port + "/v1/x"))
                    .header("X-Aprv-Token", ClientMatrix.TOKEN)
                    .header("X-Aprv-Now-Ms", "0")
                    .header("Content-Type", "application/octet-stream")
                    .timeout(Duration.ofMillis(ClientMatrix.READ_TIMEOUT))
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                    .build();
            HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (hardened) {
                boolean length = response.headers().firstValue("content-length").isPresent();
                boolean chunked = response.headers()
                        .firstValue("transfer-encoding")
                        .map(v -> v.equalsIgnoreCase("chunked"))
                        .orElse(false);
                if (!length && !chunked) {
                    response.body().close();
                    throw new IOException("a response with neither Content-Length nor chunked encoding");
                }
                long declared = response.headers().firstValueAsLong("content-length").orElse(-1L);
                if (declared > ClientMatrix.CAP) {
                    response.body().close();
                    throw new IOException("a response over " + ClientMatrix.CAP + " bytes");
                }
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            try (InputStream in = response.body()) {
                while ((n = in.read(buffer)) >= 0) {
                    if (hardened && out.size() + (long) n > ClientMatrix.CAP) {
                        throw new IOException("a response over " + ClientMatrix.CAP + " bytes");
                    }
                    out.write(buffer, 0, n);
                }
            }
            return new ClientMatrix.Answer(response.statusCode(), out.toByteArray());
        }
    }

    private JnhClients() {}
}
