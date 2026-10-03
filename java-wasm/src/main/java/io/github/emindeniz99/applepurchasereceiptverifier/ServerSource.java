package io.github.emindeniz99.applepurchasereceiptverifier;

import java.net.URI;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Where the server engine ({@link Engine#server(ServerSource...)}) finds
 * {@code aprv-server}. The engine tries its sources in the order the caller
 * gives and uses the first that works; when none works,
 * {@link Verifier#create(Config, Engine)} throws with each source's reason.
 * Immutable.
 *
 * <p>A binary that {@link #maven()}, {@link #github()} or
 * {@link #download(URI, String)} provides is checked against a pinned
 * SHA-256 before it is made executable, and again before every start; a
 * binary whose hash differs is never executed, and that source fails.</p>
 *
 * <p>Every source must lead to a server that trusts exactly the
 * {@link Config}'s roots: this library asks the server ({@code GET /v1/info})
 * and refuses one whose root fingerprints differ.</p>
 */
public final class ServerSource {

    enum Kind {
        URL,
        EXECUTABLE,
        MAVEN,
        GITHUB,
        DOWNLOAD
    }

    private static final ServerSource MAVEN = new ServerSource(Kind.MAVEN, null, null, null, null, false);
    private static final ServerSource GITHUB = new ServerSource(Kind.GITHUB, null, null, null, null, false);

    private final Kind kind;
    private final @Nullable URI uri;
    private final @Nullable String token;
    private final @Nullable Path path;
    private final @Nullable String sha256;
    private final boolean loopbackHttpForTests;

    private ServerSource(
            Kind kind,
            @Nullable URI uri,
            @Nullable String token,
            @Nullable Path path,
            @Nullable String sha256,
            boolean loopbackHttpForTests) {
        this.kind = kind;
        this.uri = uri;
        this.token = token;
        this.path = path;
        this.sha256 = sha256;
        this.loopbackHttpForTests = loopbackHttpForTests;
    }

    /**
     * An {@code aprv serve} the caller runs (a sidecar, a container),
     * reached at {@code uri}. This JVM starts nothing and needs no writable
     * or executable directory. {@code token}, when not null, is sent with
     * every request for a server that requires one. The connection uses no
     * proxy, trusts the JVM's trust store only (not a context passed to
     * {@code SSLContext.setDefault}), sends no client certificate, and
     * refuses an answer framed ambiguously; the README's "Server engine
     * sources" section says more.
     *
     * @throws NullPointerException     if {@code uri} is null
     * @throws IllegalArgumentException if {@code uri} is not an absolute
     *                                  {@code http} or {@code https} URI
     *                                  with a host, or {@code token} is empty
     */
    public static ServerSource url(URI uri, @Nullable String token) {
        Objects.requireNonNull(uri, "uri");
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (!("http".equals(scheme) || "https".equals(scheme)) || uri.getHost() == null) {
            throw new IllegalArgumentException("a server URL must be an absolute http or https URI with a host");
        }
        if (token != null && (token.isEmpty() || !token.matches("[\\x21-\\x7e]+"))) {
            throw new IllegalArgumentException(
                    "the token must be printable ASCII without spaces, and not empty; pass null for none");
        }
        return new ServerSource(Kind.URL, uri, token, null, null, false);
    }

    /**
     * The {@code aprv-server} binary at {@code path}, started as
     * {@code aprv serve --managed} and supervised. Nothing is extracted or
     * downloaded, so it suits hosts whose cache directory is {@code noexec}.
     *
     * @throws NullPointerException if {@code path} is null
     */
    public static ServerSource executable(Path path) {
        return new ServerSource(Kind.EXECUTABLE, null, null, Objects.requireNonNull(path, "path"), null, false);
    }

    /**
     * The binary for this platform from the classifier jar of this artifact
     * ({@code linux-x86_64} or {@code linux-aarch64}) on the classpath,
     * extracted into the cache directory. Its SHA-256 is pinned inside this
     * jar.
     */
    public static ServerSource maven() {
        return MAVEN;
    }

    /**
     * The binary for this platform, downloaded over HTTPS from this
     * project's GitHub Release of this version into the cache directory. Its
     * SHA-256 is pinned inside this jar.
     */
    public static ServerSource github() {
        return GITHUB;
    }

    /**
     * The binary downloaded from {@code url}, the caller's mirror, and
     * accepted only if it hashes to {@code sha256}.
     *
     * @throws NullPointerException     if an argument is null
     * @throws IllegalArgumentException if {@code url} is not an absolute
     *                                  {@code https} URI with a host, or
     *                                  {@code sha256} is not 64 hexadecimal
     *                                  digits
     */
    public static ServerSource download(URI url, String sha256) {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(sha256, "sha256");
        if (!"https".equalsIgnoreCase(url.getScheme()) || url.getHost() == null) {
            throw new IllegalArgumentException("a download URL must be an absolute https URI with a host");
        }
        if (!sha256.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("sha256 must be 64 hexadecimal digits");
        }
        return new ServerSource(Kind.DOWNLOAD, url, null, null, sha256.toLowerCase(Locale.ROOT), false);
    }

    /** {@link #download} from a loopback {@code http} server: for this library's own tests only. */
    static ServerSource downloadFromLoopbackForTests(URI url, String sha256) {
        return new ServerSource(Kind.DOWNLOAD, url, null, null, sha256.toLowerCase(Locale.ROOT), true);
    }

    Kind kind() {
        return kind;
    }

    URI uri() {
        return Objects.requireNonNull(uri);
    }

    @Nullable
    String token() {
        return token;
    }

    Path path() {
        return Objects.requireNonNull(path);
    }

    String sha256() {
        return Objects.requireNonNull(sha256);
    }

    boolean loopbackHttpForTests() {
        return loopbackHttpForTests;
    }

    @Override
    public boolean equals(@Nullable Object other) {
        if (!(other instanceof ServerSource)) {
            return false;
        }
        ServerSource that = (ServerSource) other;
        return kind == that.kind
                && Objects.equals(uri, that.uri)
                && Objects.equals(token, that.token)
                && Objects.equals(path, that.path)
                && Objects.equals(sha256, that.sha256)
                && loopbackHttpForTests == that.loopbackHttpForTests;
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, uri, token, path, sha256, loopbackHttpForTests);
    }

    /** Names the source; never shows the token. */
    @Override
    public String toString() {
        switch (kind) {
            case URL:
                return "ServerSource.url(" + uri + (token == null ? "" : ", <token>") + ")";
            case EXECUTABLE:
                return "ServerSource.executable(" + path + ")";
            case MAVEN:
                return "ServerSource.maven()";
            case GITHUB:
                return "ServerSource.github()";
            default:
                return "ServerSource.download(" + uri + ", " + sha256 + ")";
        }
    }
}
