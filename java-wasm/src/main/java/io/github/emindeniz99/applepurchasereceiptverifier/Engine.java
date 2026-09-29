package io.github.emindeniz99.applepurchasereceiptverifier;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * What runs the verifier module, {@code aprv.wasm}, for a {@link Verifier}.
 * Chosen in code and nowhere else: this library reads no system property and
 * no environment variable, so nothing outside the program can switch the
 * engine or point it at another binary.
 *
 * <ul>
 *   <li>{@link #endive()}: in this JVM. The module was compiled to JVM
 *       bytecode when this artifact was built (by Endive, a WebAssembly
 *       compiler for the JVM), so it runs as ordinary classes with the JVM's
 *       memory safety, no native code and no compiler at run time. Needs
 *       Java 11 or later.</li>
 *   <li>{@link #server(ServerSource...)}: in a separate process, the
 *       {@code aprv-server} binary, which this library starts and supervises
 *       or reaches over HTTP. Runs on Java 8. A verifier on this engine is
 *       {@link java.io.Closeable}: close it to stop a child now.</li>
 * </ul>
 *
 * <p>{@link Verifier#create(Config)} picks by the JVM version alone: Endive
 * on Java 11 and later, the server engine with its default sources on
 * Java 8. Pass an engine to {@link Verifier#create(Config, Engine)} to
 * choose; Java 11 and later may choose the server engine for the process
 * boundary. Immutable.</p>
 */
public abstract class Engine {

    Engine() {}

    /**
     * The Endive engine: the module as JVM bytecode, in this JVM, one module
     * instance per concurrent call. {@link Verifier#create(Config, Engine)}
     * throws {@link IllegalStateException} with it on a JVM older than
     * Java 11.
     */
    public static Engine endive() {
        return Endive.INSTANCE;
    }

    /**
     * The server engine, trying {@code sources} in the order given until one
     * works; with none, {@code [maven(), github()]}. With the runtime probe
     * on (the default), {@link Verifier#create(Config, Engine)} resolves the
     * sources and throws {@link IllegalStateException} with each source's
     * reason when none works; with it off, the first call does, and answers
     * {@link Reason#INTERNAL_ERROR} instead.
     *
     * @throws NullPointerException if {@code sources} or one of them is null
     */
    public static Server server(ServerSource... sources) {
        List<ServerSource> list = new ArrayList<>(sources.length);
        for (ServerSource source : sources) {
            list.add(Objects.requireNonNull(source, "source"));
        }
        if (list.isEmpty()) {
            list = Arrays.asList(ServerSource.maven(), ServerSource.github());
        }
        return new Server(Collections.unmodifiableList(list), null);
    }

    /** The engine {@link Verifier#create(Config)} uses on this JVM. */
    static Engine forThisJvm() {
        return javaFeatureVersion() >= 11 ? endive() : server();
    }

    /** Builds the verifier; the checks every engine shares have run. */
    abstract Verifier create(Config config);

    /**
     * {@link Verifier#create(Config, Engine)}: the checks every engine
     * shares, in 0.7's order (a null argument, the classpath, an empty root
     * set), then the engine's own.
     */
    static Verifier createVerifier(Config config, Engine engine) {
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(engine, "engine");
        ClasspathGuard.check(Engine.class.getClassLoader());
        if (config.roots().isEmpty()) {
            throw new IllegalArgumentException("trustedRoots must not be empty");
        }
        return engine.create(config);
    }

    /**
     * The JVM's feature version (8, 11, 17, 21, ...), from
     * {@code Runtime.version()}, which Java 8 does not have. Read through
     * reflection so this class stays Java 8 bytecode.
     */
    static int javaFeatureVersion() {
        Method version;
        try {
            version = Runtime.class.getMethod("version");
        } catch (NoSuchMethodException e) {
            return 8;
        }
        try {
            Object value = version.invoke(null);
            // feature() arrived in Java 10; major() is its Java 9 name.
            Method feature;
            try {
                feature = value.getClass().getMethod("feature");
            } catch (NoSuchMethodException e) {
                feature = value.getClass().getMethod("major");
            }
            return (Integer) feature.invoke(value);
        } catch (ReflectiveOperationException | RuntimeException e) {
            throw new IllegalStateException("cannot read this JVM's version", e);
        }
    }

    /** The Endive engine. */
    static final class Endive extends Engine {

        static final Endive INSTANCE = new Endive();

        /** The Java 11 class that loads the compiled module (src/main/java11). */
        static final String GUEST_FACTORY = "io.github.emindeniz99.applepurchasereceiptverifier.EndiveGuestFactory";

        private Endive() {}

        @Override
        Verifier create(Config config) {
            int feature = javaFeatureVersion();
            if (feature < 11) {
                throw new IllegalStateException("Engine.endive() needs Java 11 or later, and this JVM is Java "
                        + feature + "; use Engine.server(...) on Java 8");
            }
            return new WasmVerifier(config, guestFactory());
        }

        /** Loads the Endive engine, a Java 11 class, only now that it was chosen. */
        static GuestFactory guestFactory() {
            try {
                return (GuestFactory) Class.forName(GUEST_FACTORY, true, Engine.class.getClassLoader())
                        .getDeclaredConstructor()
                        .newInstance();
            } catch (InvocationTargetException e) {
                throw new IllegalStateException("the Endive engine did not load: " + e.getCause(), e.getCause());
            } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
                throw new IllegalStateException("the Endive engine did not load: " + e, e);
            }
        }

        @Override
        public String toString() {
            return "Engine.endive()";
        }
    }

    /**
     * The server engine: {@code aprv-server} in a child process this library
     * supervises, or one the user runs, reached over loopback HTTP. The
     * sources say where the binary or the server comes from; see
     * {@link ServerSource}. Immutable.
     */
    public static final class Server extends Engine {

        private final List<ServerSource> sources;
        private final @Nullable Path cacheDirectory;

        private Server(List<ServerSource> sources, @Nullable Path cacheDirectory) {
            this.sources = sources;
            this.cacheDirectory = cacheDirectory;
        }

        /**
         * The same engine, keeping extracted and downloaded server binaries in
         * {@code directory}: owner-only, each binary written as a temporary
         * file, hashed while it is written, and made executable and renamed
         * only when its SHA-256 matches the pin. A directory mounted
         * {@code noexec} cannot run them; use {@link ServerSource#url} or
         * {@link ServerSource#executable} there.
         *
         * @throws NullPointerException if {@code directory} is null
         */
        public Server cacheDirectory(Path directory) {
            return new Server(sources, Objects.requireNonNull(directory, "directory"));
        }

        /** The sources, in the order they are tried; unmodifiable. */
        public List<ServerSource> sources() {
            return sources;
        }

        /**
         * The directory set with {@link #cacheDirectory(Path)}, or
         * {@code null} for the default, which the server engine fixes when it
         * lands.
         */
        public @Nullable Path cacheDirectory() {
            return cacheDirectory;
        }

        @Override
        Verifier create(Config config) {
            boolean probe = config.runtimeProbe();
            return new ServerVerifier(
                    config,
                    () -> {
                        try {
                            return ServerSources.open(config, this);
                        } catch (IllegalStateException e) {
                            if (probe) {
                                throw e;
                            }
                            throw new ServerProcessFailure(e.getMessage(), e);
                        }
                    },
                    probe);
        }

        @Override
        public boolean equals(@Nullable Object other) {
            return other instanceof Server
                    && sources.equals(((Server) other).sources)
                    && Objects.equals(cacheDirectory, ((Server) other).cacheDirectory);
        }

        @Override
        public int hashCode() {
            return 31 * sources.hashCode() + Objects.hashCode(cacheDirectory);
        }

        @Override
        public String toString() {
            return "Engine.server(" + sources + (cacheDirectory == null ? "" : ", cacheDirectory=" + cacheDirectory)
                    + ")";
        }
    }
}
