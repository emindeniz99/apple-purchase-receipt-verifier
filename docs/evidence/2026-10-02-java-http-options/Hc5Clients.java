package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.TimeUnit;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.util.Timeout;

/**
 * Apache HttpClient 5.6.4 classic. {@link #hardened()} is configured as the
 * server engine would configure it: no redirects, no automatic retries, no
 * content decoding, no cookies, no auth cache, no system properties
 * (HttpClients.custom() reads none unless useSystemProperties() is called),
 * plus the two checks HttpClient does not make for us: a body framed by
 * neither Content-Length nor chunks is refused, and a body over the cap is
 * refused rather than cut. {@link #defaults()} is HttpClients.createDefault().
 */
final class Hc5Clients {

    static ClientMatrix.Client hardened() {
        return new Hc5(
                "hc5-hardened",
                HttpClients.custom()
                        .setConnectionManager(PoolingHttpClientConnectionManagerBuilder.create()
                                .setDefaultConnectionConfig(ConnectionConfig.custom()
                                        .setConnectTimeout(Timeout.ofSeconds(5))
                                        .setSocketTimeout(Timeout.ofMilliseconds(ClientMatrix.READ_TIMEOUT))
                                        .build())
                                .build())
                        .setDefaultRequestConfig(RequestConfig.custom()
                                .setResponseTimeout(ClientMatrix.READ_TIMEOUT, TimeUnit.MILLISECONDS)
                                .build())
                        .disableRedirectHandling()
                        .disableAutomaticRetries()
                        .disableContentCompression()
                        .disableCookieManagement()
                        .disableAuthCaching()
                        .disableDefaultUserAgent()
                        .build(),
                true);
    }

    static ClientMatrix.Client defaults() {
        return new Hc5("hc5-default", HttpClients.createDefault(), false);
    }

    static final class Hc5 implements ClientMatrix.Client {
        private final String name;
        private final CloseableHttpClient client;
        private final boolean checks;

        Hc5(String name, CloseableHttpClient client, boolean checks) {
            this.name = name;
            this.client = client;
            this.checks = checks;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public ClientMatrix.Answer post(String scheme, String host, int port, byte[] body) throws Exception {
            HttpPost post = new HttpPost(scheme + "://" + host + ":" + port + "/v1/x");
            post.setHeader("X-Aprv-Token", ClientMatrix.TOKEN);
            post.setHeader("X-Aprv-Now-Ms", "0");
            post.setEntity(new ByteArrayEntity(body, ContentType.APPLICATION_OCTET_STREAM));
            try {
                return client.execute(post, response -> {
                    HttpEntity entity = response.getEntity();
                    byte[] bytes = new byte[0];
                    if (entity != null) {
                        // A refusal cancels the request first: otherwise execute() drains the rest of
                        // the body to reuse the connection, which waits for the read timeout.
                        if (checks && entity.getContentLength() < 0 && !entity.isChunked()) {
                            post.cancel();
                            throw new IOException("a response with neither Content-Length nor chunked encoding");
                        }
                        if (checks && entity.getContentLength() > ClientMatrix.CAP) {
                            post.cancel();
                            throw new IOException("a response over " + ClientMatrix.CAP + " bytes");
                        }
                        bytes = read(entity.getContent(), checks ? ClientMatrix.CAP : Integer.MAX_VALUE - 8);
                    }
                    return new ClientMatrix.Answer(response.getCode(), bytes);
                });
            } finally {
                client.close();
            }
        }

        private static byte[] read(InputStream in, int cap) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            try (InputStream stream = in) {
                while ((n = stream.read(buffer)) >= 0) {
                    if (out.size() + (long) n > cap) {
                        throw new IOException("a response over " + cap + " bytes");
                    }
                    out.write(buffer, 0, n);
                }
            }
            return out.toByteArray();
        }
    }

    private Hc5Clients() {}
}
