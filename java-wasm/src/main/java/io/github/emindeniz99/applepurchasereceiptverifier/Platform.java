package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import org.jspecify.annotations.Nullable;

/**
 * The platform facts the server engine needs, read from the JDK and nowhere
 * else: the operating system, the CPU architecture and the user's home
 * directory. These are the JDK's own standard properties ({@code os.name},
 * {@code os.arch}, {@code user.home}), read here and only here; this library
 * defines no property or environment variable of its own, and
 * {@code SourceRulesTest} holds every other source to that.
 */
final class Platform {

    private Platform() {}

    static String osName() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    }

    static String osArch() {
        return System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
    }

    static boolean windows() {
        return osName().startsWith("windows");
    }

    static boolean linux() {
        return osName().startsWith("linux");
    }

    /**
     * The target triple of the {@code aprv-server} release asset for this
     * platform ({@code x86_64-unknown-linux-musl}, ...), or {@code null} when
     * no build exists for it.
     */
    static @Nullable String target() {
        return target(osName(), osArch());
    }

    static @Nullable String target(String os, String arch) {
        String cpu;
        if (arch.equals("amd64") || arch.equals("x86_64")) {
            cpu = "x86_64";
        } else if (arch.equals("aarch64") || arch.equals("arm64")) {
            cpu = "aarch64";
        } else {
            return null;
        }
        if (os.startsWith("linux")) {
            return cpu + "-unknown-linux-musl";
        }
        if (os.startsWith("mac")) {
            return cpu + "-apple-darwin";
        }
        if (os.startsWith("windows")) {
            return cpu + "-pc-windows-msvc";
        }
        return null;
    }

    /** The release asset's file name for {@code target}: {@code aprv-<target>}, plus {@code .exe} on Windows. */
    static String assetName(String target) {
        return "aprv-" + target + (target.endsWith("-windows-msvc") ? ".exe" : "");
    }

    /**
     * The default cache directory for server binaries: the user's own cache
     * directory, {@code ~/.cache/aprv} on Linux and other Unix systems,
     * {@code ~/Library/Caches/aprv} on macOS and
     * {@code %USERPROFILE%\AppData\Local\aprv\cache} on Windows.
     * {@code XDG_CACHE_HOME} is not consulted: pass
     * {@link Engine.Server#cacheDirectory(Path)} for another directory.
     */
    static Path defaultCacheDirectory() {
        Path home = Paths.get(System.getProperty("user.home", "."));
        String os = osName();
        if (os.startsWith("mac")) {
            return home.resolve("Library").resolve("Caches").resolve("aprv");
        }
        if (os.startsWith("windows")) {
            return home.resolve("AppData").resolve("Local").resolve("aprv").resolve("cache");
        }
        return home.resolve(".cache").resolve("aprv");
    }
}
