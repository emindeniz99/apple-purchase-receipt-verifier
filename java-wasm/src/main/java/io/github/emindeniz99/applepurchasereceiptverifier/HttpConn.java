package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.jspecify.annotations.Nullable;

/**
 * One keep-alive HTTP/1.1 connection to {@code aprv-server}. Each request
 * goes out in a single write with {@code TCP_NODELAY}: HttpURLConnection
 * writes the headers and the body separately, which cost about 1.5 ms per
 * POST against a loopback server (rust-core spikes, "Sidecar"). The response
 * is read by {@code Content-Length} or chunked encoding, up to
 * {@link #MAX_RESPONSE} bytes. Not thread-safe: {@link ServerConnection}
 * pools these, one request at a time on each.
 */
final class HttpConn implements Closeable {

    /** Larger than any answer the module writes (the payload of a 3 MiB receipt, as JSON). */
    static final int MAX_RESPONSE = 64 << 20;

    private static final int MAX_LINE = 16 << 10;
    private static final int MAX_HEADERS = 100;

    /** Where the server is: host, port, TLS or not, a base path, the token, and which child it is. */
    static final class Target {
        final String host;
        final int port;
        final boolean tls;
        final String basePath;
        final @Nullable String token;
        final int generation;

        Target(String host, int port, boolean tls, String basePath, @Nullable String token, int generation) {
            this.host = host;
            this.port = port;
            this.tls = tls;
            this.basePath = basePath;
            this.token = token;
            this.generation = generation;
        }
    }

    /** A complete response. */
    static final class Response {
        final int status;
        final String contentType;
        final byte[] body;

        Response(int status, String contentType, byte[] body) {
            this.status = status;
            this.contentType = contentType;
            this.body = body;
        }

        String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    final Target target;
    private final Socket socket;
    private final OutputStream out;
    private final InputStream in;
    private boolean reusable = true;

    HttpConn(Target target, int connectTimeoutMillis, int readTimeoutMillis) throws IOException {
        this.target = target;
        Socket plain = new Socket();
        try {
            plain.setTcpNoDelay(true);
            plain.connect(new InetSocketAddress(target.host, target.port), connectTimeoutMillis);
            plain.setSoTimeout(readTimeoutMillis);
            if (target.tls) {
                SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault())
                        .createSocket(plain, target.host, target.port, true);
                SSLParameters parameters = tls.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                tls.setSSLParameters(parameters);
                tls.startHandshake();
                socket = tls;
            } else {
                socket = plain;
            }
            out = socket.getOutputStream();
            in = new BufferedInputStream(socket.getInputStream(), 16 << 10);
        } catch (IOException | RuntimeException e) {
            plain.close();
            throw e;
        }
    }

    /** Whether the connection can carry another request. */
    boolean reusable() {
        return reusable;
    }

    /**
     * Sends one request and reads its response. {@code nowMs}, when given,
     * goes out as {@code X-Aprv-Now-Ms}.
     *
     * @throws IOException when the connection fails or the answer is not HTTP;
     *     the connection is then not reusable
     */
    Response exchange(String method, String path, byte[] body, @Nullable Long nowMs) throws IOException {
        reusable = false;
        StringBuilder head = new StringBuilder(256)
                .append(method)
                .append(' ')
                .append(target.basePath)
                .append(path)
                .append(" HTTP/1.1\r\nHost: ")
                .append(target.host)
                .append(':')
                .append(target.port)
                .append("\r\n");
        if (target.token != null) {
            head.append("X-Aprv-Token: ").append(target.token).append("\r\n");
        }
        if (nowMs != null) {
            head.append("X-Aprv-Now-Ms: ").append(Long.toUnsignedString(nowMs)).append("\r\n");
        }
        head.append("Content-Type: application/octet-stream\r\nContent-Length: ")
                .append(body.length)
                .append("\r\n\r\n");
        byte[] headBytes = head.toString().getBytes(StandardCharsets.US_ASCII);
        byte[] request = new byte[headBytes.length + body.length];
        System.arraycopy(headBytes, 0, request, 0, headBytes.length);
        System.arraycopy(body, 0, request, headBytes.length, body.length);
        out.write(request);
        out.flush();

        String statusLine = line();
        if (!statusLine.startsWith("HTTP/1.") || statusLine.length() < 12 || statusLine.charAt(8) != ' ') {
            throw new IOException("not an HTTP/1.x status line");
        }
        int status;
        try {
            status = Integer.parseInt(statusLine.substring(9, 12));
        } catch (NumberFormatException e) {
            throw new IOException("not an HTTP status code", e);
        }
        long length = -1;
        boolean chunked = false;
        boolean close = statusLine.startsWith("HTTP/1.0");
        String contentType = "";
        for (int count = 0; ; count++) {
            String header = line();
            if (header.isEmpty()) {
                break;
            }
            if (count >= MAX_HEADERS) {
                throw new IOException("too many response headers");
            }
            int colon = header.indexOf(':');
            if (colon <= 0) {
                throw new IOException("a malformed response header");
            }
            String name = header.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = header.substring(colon + 1).trim();
            if (name.equals("content-length")) {
                try {
                    length = Long.parseLong(value);
                } catch (NumberFormatException e) {
                    throw new IOException("a malformed Content-Length", e);
                }
            } else if (name.equals("transfer-encoding")) {
                chunked = value.toLowerCase(Locale.ROOT).contains("chunked");
            } else if (name.equals("connection")) {
                close = value.toLowerCase(Locale.ROOT).contains("close");
            } else if (name.equals("content-type")) {
                contentType = value;
            }
        }
        byte[] responseBody;
        if (chunked) {
            responseBody = chunked();
        } else if (length >= 0) {
            if (length > MAX_RESPONSE) {
                throw new IOException("a response over " + MAX_RESPONSE + " bytes");
            }
            responseBody = exactly((int) length);
        } else if (status == 204 || status == 304 || method.equals("HEAD")) {
            responseBody = new byte[0];
        } else {
            throw new IOException("a response with neither Content-Length nor chunked encoding");
        }
        reusable = !close;
        return new Response(status, contentType, responseBody);
    }

    private byte[] chunked() throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            String size = line();
            int semicolon = size.indexOf(';');
            int n;
            try {
                n = Integer.parseInt((semicolon < 0 ? size : size.substring(0, semicolon)).trim(), 16);
            } catch (NumberFormatException e) {
                throw new IOException("a malformed chunk size", e);
            }
            if (n < 0 || body.size() + (long) n > MAX_RESPONSE) {
                throw new IOException("a response over " + MAX_RESPONSE + " bytes");
            }
            if (n == 0) {
                while (!line().isEmpty()) {
                    // trailers, ignored
                }
                return body.toByteArray();
            }
            body.write(exactly(n));
            if (!line().isEmpty()) {
                throw new IOException("a chunk not followed by CRLF");
            }
        }
    }

    private byte[] exactly(int n) throws IOException {
        byte[] bytes = new byte[n];
        int read = 0;
        while (read < n) {
            int r = in.read(bytes, read, n - read);
            if (r < 0) {
                throw new EOFException("the connection closed inside a response");
            }
            read += r;
        }
        return bytes;
    }

    private String line() throws IOException {
        StringBuilder line = new StringBuilder(64);
        while (true) {
            int c = in.read();
            if (c < 0) {
                throw new EOFException("the connection closed");
            }
            if (c == '\n') {
                return line.toString();
            }
            if (c != '\r') {
                if (line.length() >= MAX_LINE) {
                    throw new IOException("a response line over " + MAX_LINE + " bytes");
                }
                line.append((char) c);
            }
        }
    }

    @Override
    public void close() {
        reusable = false;
        try {
            socket.close();
        } catch (IOException e) {
            // closing: nothing to do
        }
    }
}
