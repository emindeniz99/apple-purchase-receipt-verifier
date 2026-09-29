package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.Nullable;

/**
 * The server binaries of {@link ServerSource#maven()}, {@link ServerSource#github()}
 * and {@link ServerSource#download}: the SHA-256 pins, and the cache they are
 * installed into (ARCHITECTURE.md §7.8, THREAT-MODEL.md §7).
 *
 * <p>The cache directory is owner-only and not a symbolic link. A binary is
 * written there as a temporary owner-only file, hashed while it streams, and
 * only when the hash is the pin is it made executable and renamed to
 * {@code aprv-<sha256>}; a mismatch is deleted without ever being executable.
 * An installed binary is hashed again before every start. One install runs at
 * a time per directory: a monitor between this JVM's threads and a
 * {@link FileLock} between processes, so several JVMs starting at once
 * download once.</p>
 */
final class ServerBinary {

    private ServerBinary() {}

    /** The pins resource inside this jar: {@code sha256sum} lines, {@code <hex>  aprv-<target>[.exe]}. */
    static final String PINS = "server/SHA256SUMS";

    /** Where a classifier jar keeps the binary for {@code target}: {@code server/aprv-<target>[.exe]}. */
    static String classifierResource(String target) {
        return "server/" + Platform.assetName(target);
    }

    /** The release assets of this version. */
    static final String GITHUB_RELEASES =
            "https://github.com/emindeniz99/apple-purchase-receipt-verifier/releases/download/v";

    static URI githubAsset(String target) {
        return URI.create(GITHUB_RELEASES + Version.CURRENT + "/" + Platform.assetName(target));
    }

    /** A download is refused past this size; the static server is about 12 MB. */
    static final long MAX_BINARY = 128L << 20;

    /** How many downloads this JVM performed, for tests. */
    static final AtomicInteger DOWNLOADS = new AtomicInteger();

    private static final Map<Path, Object> DIRECTORY_LOCKS = new ConcurrentHashMap<>();

    /** The SHA-256 pinned in this jar for {@code target}'s release asset, or {@code null}. */
    static @Nullable String pin(String target) {
        return pins().get(Platform.assetName(target));
    }

    static Map<String, String> pins() {
        Map<String, String> pins = new HashMap<>();
        InputStream in = ServerBinary.class.getResourceAsStream(PINS);
        if (in == null) {
            return pins;
        }
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.US_ASCII))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] fields = line.split("\\s+\\*?", 2);
                if (fields.length == 2 && fields[0].matches("[0-9a-f]{64}")) {
                    pins.put(fields[1].trim(), fields[0]);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("the server pins in this jar cannot be read", e);
        }
        return pins;
    }

    /** Opens the source bytes to install; called under the directory lock, only when the cache lacks them. */
    interface Fetch {
        InputStream open() throws IOException;
    }

    /**
     * The installed binary {@code aprv-<sha256>} in {@code directory},
     * installing it from {@code fetch} first when it is missing or no longer
     * hashes to {@code sha256}.
     *
     * @throws IOException if the directory is not safe, the fetch fails, or the
     *     bytes do not hash to {@code sha256} (nothing is left behind then)
     */
    static Path install(Path directory, String sha256, Fetch fetch) throws IOException {
        Path dir = ownerOnlyDirectory(directory);
        Path target = dir.resolve("aprv-" + sha256 + (Platform.windows() ? ".exe" : ""));
        synchronized (DIRECTORY_LOCKS.computeIfAbsent(dir, d -> new Object())) {
            try (FileChannel channel = FileChannel.open(
                            dir.resolve(".lock"), StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                    FileLock lock = channel.lock()) {
                if (Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
                    if (sha256(target).equals(sha256)) {
                        return target;
                    }
                    // Changed after it was installed: never run it, fetch it again.
                    Files.delete(target);
                }
                Path temporary = temporaryFile(dir);
                try {
                    String got;
                    try (InputStream in = fetch.open()) {
                        got = copyAndHash(in, temporary);
                    }
                    if (!got.equals(sha256)) {
                        throw new IOException("the binary hashes to " + got + ", not the pinned " + sha256
                                + "; it was not made executable");
                    }
                    executable(temporary);
                    try {
                        Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
                    } catch (AtomicMoveNotSupportedException | FileAlreadyExistsException e) {
                        Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
                    }
                    return target;
                } finally {
                    Files.deleteIfExists(temporary);
                }
            }
        }
    }

    /** Hashes an installed binary again before it starts; a mismatch is deleted, never run. */
    static void verifyBeforeStart(Path binary, String sha256) {
        String got;
        try {
            got = sha256(binary);
        } catch (IOException e) {
            throw new ServerProcessFailure("cannot read " + binary + " to check it before starting it", e);
        }
        if (!got.equals(sha256)) {
            try {
                Files.deleteIfExists(binary);
            } catch (IOException e) {
                // reported below either way
            }
            throw new ServerProcessFailure(binary + " changed after it was installed (sha256 " + got + ", pinned "
                    + sha256 + "); it was deleted and not started");
        }
    }

    /**
     * Downloads {@code uri} over HTTPS, following redirects (release assets
     * redirect to a download host; the pin decides, not the host). The JDK's
     * own proxy settings apply.
     */
    static InputStream download(URI uri, boolean allowLoopbackHttpForTests) throws IOException {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        boolean loopbackTest = allowLoopbackHttpForTests
                && scheme.equals("http")
                && ("127.0.0.1".equals(uri.getHost()) || "localhost".equals(uri.getHost()));
        if (!scheme.equals("https") && !loopbackTest) {
            throw new IOException("refusing a download that is not HTTPS: " + uri);
        }
        URLConnection connection = uri.toURL().openConnection();
        HttpURLConnection http = (HttpURLConnection) connection;
        http.setInstanceFollowRedirects(true);
        http.setConnectTimeout(15_000);
        http.setReadTimeout(60_000);
        int status = http.getResponseCode();
        if (status != 200) {
            http.disconnect();
            throw new IOException("GET " + uri + " answered HTTP " + status);
        }
        if (!loopbackTest && !"https".equalsIgnoreCase(http.getURL().getProtocol())) {
            http.disconnect();
            throw new IOException("the download of " + uri + " was redirected off HTTPS");
        }
        DOWNLOADS.incrementAndGet();
        return http.getInputStream();
    }

    /**
     * Why a binary would not start, and what to do: an {@code EACCES} on a
     * file that has its execute bit is a {@code noexec} mount.
     */
    static String explainStartFailure(Path binary, IOException e) {
        String message = "cannot start " + binary + ": " + e.getMessage();
        return noexec(binary) ? message + ". " + NOEXEC_ADVICE : message;
    }

    static final String NOEXEC_ADVICE = "Its directory is on a file system mounted noexec, which cannot run"
            + " binaries; use ServerSource.url(...) with a server you run, ServerSource.executable(...) with a"
            + " binary on an exec-allowed mount, or cacheDirectory(...) on an exec-allowed mount";

    /**
     * Whether {@code path} is on a mount with the {@code noexec} option, read
     * from {@code /proc/self/mountinfo} on Linux; false where that cannot be
     * told.
     */
    static boolean noexec(Path path) {
        if (!Platform.linux()) {
            return false;
        }
        Path mountinfo = Paths.get("/proc/self/mountinfo");
        if (!Files.isReadable(mountinfo)) {
            return false;
        }
        Path real;
        try {
            real = (Files.exists(path) ? path : path.getParent()).toRealPath();
        } catch (IOException | RuntimeException e) {
            return false;
        }
        try {
            return noexec(real, Files.readAllLines(mountinfo, StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /** Whether the mount holding {@code real} (a real path) is {@code noexec}, by the given mountinfo lines. */
    static boolean noexec(Path real, List<String> mountinfo) {
        String best = null;
        boolean bestNoexec = false;
        for (String line : mountinfo) {
            String[] fields = line.split(" ");
            if (fields.length < 6) {
                continue;
            }
            String mountPoint = unescape(fields[4]);
            if (real.startsWith(Paths.get(mountPoint)) && (best == null || mountPoint.length() >= best.length())) {
                best = mountPoint;
                bestNoexec = (',' + fields[5] + ',').contains(",noexec,");
            }
        }
        return bestNoexec;
    }

    /** mountinfo escapes space, tab, newline and backslash as octal. */
    private static String unescape(String field) {
        StringBuilder out = new StringBuilder(field.length());
        for (int i = 0; i < field.length(); i++) {
            char c = field.charAt(i);
            if (c == '\\' && i + 3 < field.length()) {
                try {
                    out.append((char) Integer.parseInt(field.substring(i + 1, i + 4), 8));
                    i += 3;
                    continue;
                } catch (NumberFormatException e) {
                    // not an escape
                }
            }
            out.append(c);
        }
        return out.toString();
    }

    /**
     * Creates {@code directory} owner-only if it is missing, and refuses one
     * that is a symbolic link, belongs to another user, or others can write.
     */
    static Path ownerOnlyDirectory(Path directory) throws IOException {
        Path dir = directory.toAbsolutePath().normalize();
        boolean posix = Files.getFileStore(existingAncestor(dir)).supportsFileAttributeView("posix");
        if (!Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
            if (posix) {
                Files.createDirectories(
                        dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            } else {
                Files.createDirectories(dir);
            }
        }
        if (Files.isSymbolicLink(dir) || !Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("the cache directory " + dir + " is a symbolic link or not a directory");
        }
        if (posix) {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(dir, LinkOption.NOFOLLOW_LINKS);
            if (permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                throw new IOException("the cache directory " + dir + " is writable by others; make it owner-only");
            }
            Path probe = Files.createTempFile(dir, ".owner-", ".tmp");
            try {
                UserPrincipal me = Files.getOwner(probe);
                if (!me.equals(Files.getOwner(dir, LinkOption.NOFOLLOW_LINKS))) {
                    throw new IOException("the cache directory " + dir + " belongs to another user");
                }
            } finally {
                Files.deleteIfExists(probe);
            }
        }
        return dir;
    }

    private static Path existingAncestor(Path path) {
        Path p = path;
        while (p != null && !Files.exists(p)) {
            p = p.getParent();
        }
        return p != null ? p : path.getRoot();
    }

    private static Path temporaryFile(Path dir) throws IOException {
        if (Files.getFileStore(dir).supportsFileAttributeView("posix")) {
            return Files.createTempFile(
                    dir,
                    ".part-",
                    ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        }
        return Files.createTempFile(dir, ".part-", ".tmp");
    }

    private static void executable(Path file) throws IOException {
        if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("r-x------"));
        }
    }

    private static String copyAndHash(InputStream in, Path to) throws IOException {
        MessageDigest digest = sha256Digest();
        long total = 0;
        try (OutputStream out = Files.newOutputStream(to, StandardOpenOption.TRUNCATE_EXISTING)) {
            byte[] buffer = new byte[64 << 10];
            int n;
            while ((n = in.read(buffer)) > 0) {
                total += n;
                if (total > MAX_BINARY) {
                    throw new IOException("the binary is larger than " + MAX_BINARY + " bytes");
                }
                digest.update(buffer, 0, n);
                out.write(buffer, 0, n);
            }
        }
        return hex(digest.digest());
    }

    static String sha256(Path file) throws IOException {
        MessageDigest digest = sha256Digest();
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[64 << 10];
            int n;
            while ((n = in.read(buffer)) > 0) {
                digest.update(buffer, 0, n);
            }
        }
        return hex(digest.digest());
    }

    static String sha256(byte[] bytes) {
        return hex(sha256Digest().digest(bytes));
    }

    static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("this JVM has no SHA-256", e);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >> 4) & 0xf, 16));
            out.append(Character.forDigit(b & 0xf, 16));
        }
        return out.toString();
    }
}
