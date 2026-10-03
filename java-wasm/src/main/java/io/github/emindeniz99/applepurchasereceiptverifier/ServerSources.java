package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Turns the server engine's sources into one working server, trying them in
 * the caller's order (ARCHITECTURE.md §7.8). A source works when the server
 * it names answers {@code GET /v1/info}, trusts exactly the
 * {@link Config}'s roots and states the module's {@code max_input_bytes};
 * otherwise it fails with a reason and the next is tried. When none works,
 * {@link #open} throws with every reason.
 */
final class ServerSources {

    private ServerSources() {}

    static ServerConnection open(Config config, Engine.Server engine) {
        Path cache = engine.cacheDirectory() != null ? engine.cacheDirectory() : Platform.defaultCacheDirectory();
        String rootsLine = InitConfig.json(config.roots());
        Set<String> fingerprints = InitConfig.fingerprints(config.roots());
        List<String> reasons = new ArrayList<>();
        for (ServerSource source : engine.sources()) {
            ServerConnection connection = null;
            try {
                connection = connect(source, cache, rootsLine);
                connection.maxInputBytes(checkInfo(connection, fingerprints));
                return connection;
            } catch (InitRefused e) {
                // Every source runs the same module, which would refuse the same roots.
                throw new IllegalArgumentException(
                        "the verifier module refused a root in the config: " + e.getMessage(), e);
            } catch (IOException | RuntimeException e) {
                if (connection != null) {
                    connection.close();
                }
                reasons.add(source + ": " + e.getMessage());
            }
        }
        throw new IllegalStateException("no aprv-server source worked: " + String.join("; ", reasons));
    }

    private static ServerConnection connect(ServerSource source, Path cache, String rootsLine) throws IOException {
        switch (source.kind()) {
            case URL:
                return ServerConnection.fixed(target(source.uri(), source.token()), source.toString());
            case EXECUTABLE:
                return ServerConnection.managed(new ServerProcess(source.path(), null, rootsLine), source.toString());
            case MAVEN: {
                String target = platformTarget();
                if (!target.endsWith("-linux-musl")) {
                    throw new IOException("the classifier jars carry Linux binaries only, and this is " + target
                            + "; use github() or download(...)");
                }
                String pin = pin(target);
                String resource = ServerBinary.classifierResource(target);
                String classifier = "linux-" + target.substring(0, target.indexOf('-'));
                Path binary = ServerBinary.install(cache, pin, () -> {
                    InputStream in = ServerBinary.class.getResourceAsStream(resource);
                    if (in == null) {
                        throw new IOException("the " + classifier + " classifier jar of this artifact is not on the"
                                + " classpath (no " + resource + ")");
                    }
                    return in;
                });
                return ServerConnection.managed(new ServerProcess(binary, pin, rootsLine), source.toString());
            }
            case GITHUB: {
                String target = platformTarget();
                String pin = pin(target);
                URI asset = ServerBinary.githubAsset(target);
                Path binary = ServerBinary.install(cache, pin, () -> ServerBinary.download(asset, false));
                return ServerConnection.managed(new ServerProcess(binary, pin, rootsLine), source.toString());
            }
            default: {
                URI uri = source.uri();
                boolean loopback = source.loopbackHttpForTests();
                Path binary = ServerBinary.install(cache, source.sha256(), () -> ServerBinary.download(uri, loopback));
                return ServerConnection.managed(
                        new ServerProcess(binary, source.sha256(), rootsLine), source.toString());
            }
        }
    }

    private static String platformTarget() throws IOException {
        String target = Platform.target();
        if (target == null) {
            throw new IOException("no aprv-server build exists for " + Platform.osName() + " on " + Platform.osArch());
        }
        return target;
    }

    private static String pin(String target) throws IOException {
        String pin = ServerBinary.pin(target);
        if (pin == null) {
            throw new IOException("this jar pins no SHA-256 for " + Platform.assetName(target));
        }
        return pin;
    }

    /** A URL source's address: host, port, TLS and base path. */
    static HttpConn.Target target(URI uri, @Nullable String token) {
        boolean tls = "https".equals(uri.getScheme().toLowerCase(Locale.ROOT));
        String host = uri.getHost();
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        int port = uri.getPort() >= 0 ? uri.getPort() : tls ? 443 : 80;
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        while (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return new HttpConn.Target(host, port, tls, path, token, 0);
    }

    /**
     * Refuses a server that does not answer {@code GET /v1/info}, or that
     * trusts other roots than the config: it would run something else. Returns
     * the {@code limits.max_input_bytes} the server read from its module's
     * {@code init} answer (DECISIONS.md R42); a server that states none runs
     * a module older than this library and is refused too.
     */
    static int checkInfo(ServerConnection connection, Set<String> fingerprints) {
        HttpConn.Response response = connection.send("GET", "/v1/info", new byte[0], null);
        if (response.status != 200) {
            throw ServerJson.problem(response);
        }
        Object info = ServerJson.parse(response.text());
        Object roots = ServerJson.member(ServerJson.member(info, "roots"), "sha256");
        Set<String> served = new HashSet<>();
        if (roots instanceof List) {
            for (Object root : (List<?>) roots) {
                served.add(String.valueOf(root).toLowerCase(Locale.ROOT));
            }
        }
        if (!served.equals(fingerprints)) {
            throw new IllegalStateException("the server trusts other roots than the Config (its root SHA-256s " + served
                    + ", the Config's " + fingerprints + ")");
        }
        Object max = ServerJson.member(ServerJson.member(info, "limits"), "max_input_bytes");
        if (!(max instanceof Long)
                || ((Number) max).longValue() < 1
                || ((Number) max).longValue() > Integer.MAX_VALUE) {
            throw new IllegalStateException("the server states no limits.max_input_bytes in GET /v1/info, so its"
                    + " module is older than this library");
        }
        return ((Number) max).intValue();
    }
}
