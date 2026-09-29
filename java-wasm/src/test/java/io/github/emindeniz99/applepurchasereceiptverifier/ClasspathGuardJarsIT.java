package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The two real jars on one classpath, in both orders: {@code Verifier.create}
 * throws the guard's {@link IllegalStateException} whichever jar's classes
 * load first. Also checks that this artifact keeps the main artifact's
 * public API: every public type, constructor, method and field of the main
 * jar exists here with the same signature.
 *
 * <p>Runs in the {@code classpath-guard} profile after {@code package}
 * (failsafe), and needs the main artifact's jar built first:
 * {@code mvn -f java package -DskipTests}, then
 * {@code mvn -f java-wasm verify -Pclasspath-guard}.</p>
 */
class ClasspathGuardJarsIT {

    private static final String PACKAGE = "io.github.emindeniz99.applepurchasereceiptverifier";

    private static Path only(Path directory, String prefix) throws Exception {
        List<Path> found;
        try (Stream<Path> list = Files.list(directory)) {
            found = list.filter(p -> {
                        String name = p.getFileName().toString();
                        return name.startsWith(prefix)
                                && name.endsWith(".jar")
                                && !name.endsWith("-tests.jar")
                                && !name.endsWith("-sources.jar")
                                && !name.endsWith("-javadoc.jar")
                                && name.substring(prefix.length()).matches("[0-9].*");
                    })
                    .collect(Collectors.toList());
        }
        assertEquals(1, found.size(), "one " + prefix + "<version>.jar in " + directory + ": " + found);
        return found.get(0);
    }

    private static Path mainJar() throws Exception {
        Path target = Paths.get("..", "java", "target");
        assertTrue(Files.isDirectory(target), "build the main artifact first: mvn -f java package -DskipTests");
        return only(target, "apple-purchase-receipt-verifier-");
    }

    private static Path wasmJar() throws Exception {
        return only(Paths.get("target"), "apple-purchase-receipt-verifier-wasm-");
    }

    private static List<URL> libraries() throws Exception {
        List<URL> urls = new ArrayList<>();
        File[] jars = Paths.get("target", "guard-lib").toFile().listFiles((dir, name) -> name.endsWith(".jar"));
        assertTrue(jars != null && jars.length >= 4, "target/guard-lib holds the dependencies");
        for (File jar : jars) {
            urls.add(jar.toURI().toURL());
        }
        return urls;
    }

    private static URLClassLoader loader(Path... jars) throws Exception {
        List<URL> urls = new ArrayList<>();
        for (Path jar : jars) {
            urls.add(jar.toUri().toURL());
        }
        urls.addAll(libraries());
        return new URLClassLoader(urls.toArray(new URL[0]), null);
    }

    @Test
    void bothJarsOnOneClasspathFailAtCreateInEitherOrder() throws Exception {
        Path main = mainJar();
        Path wasm = wasmJar();
        for (Path[] order : new Path[][] {{main, wasm}, {wasm, main}}) {
            try (URLClassLoader loader = loader(order)) {
                Class<?> config = loader.loadClass(PACKAGE + ".Config");
                Class<?> verifier = loader.loadClass(PACKAGE + ".Verifier");
                Object defaults = config.getMethod("defaults").invoke(null);
                Method create = verifier.getMethod("create", config);
                InvocationTargetException e =
                        assertThrows(InvocationTargetException.class, () -> create.invoke(null, defaults));
                Throwable cause = e.getCause();
                assertTrue(cause instanceof IllegalStateException, String.valueOf(cause));
                assertTrue(cause.getMessage().contains("Depend on exactly one"), cause.getMessage());
                System.out.println("classpath guard (" + order[0].getFileName() + " first): " + cause.getMessage());
            }
        }
    }

    /** Each jar alone gets past the guard. */
    @Test
    void eachJarAloneGetsPastTheGuard() throws Exception {
        try (URLClassLoader loader = loader(mainJar())) {
            Class<?> config = loader.loadClass(PACKAGE + ".Config");
            Object verifier = loader.loadClass(PACKAGE + ".Verifier")
                    .getMethod("create", config)
                    .invoke(null, config.getMethod("defaults").invoke(null));
            assertEquals(PACKAGE + ".DefaultVerifier", verifier.getClass().getName());
        }
        try (URLClassLoader loader = loader(wasmJar())) {
            Class<?> config = loader.loadClass(PACKAGE + ".Config");
            Class<?> engine = loader.loadClass(PACKAGE + ".Engine");
            Method create = loader.loadClass(PACKAGE + ".Verifier").getMethod("create", config, engine);
            Object server = engine.getMethod("server", loader.loadClass("[L" + PACKAGE + ".ServerSource;"))
                    .invoke(null, (Object)
                            java.lang.reflect.Array.newInstance(loader.loadClass(PACKAGE + ".ServerSource"), 0));
            InvocationTargetException pending = assertThrows(
                    InvocationTargetException.class,
                    () -> create.invoke(null, config.getMethod("defaults").invoke(null), server));
            assertTrue(pending.getCause() instanceof UnsupportedOperationException, String.valueOf(pending.getCause()));
        }
    }

    @Test
    void thisArtifactKeepsTheMainArtifactsPublicApi() throws Exception {
        Set<String> main;
        Set<String> wasm;
        try (URLClassLoader loader = loader(mainJar())) {
            main = publicApi(mainJar(), loader);
        }
        try (URLClassLoader loader = loader(wasmJar())) {
            wasm = publicApi(wasmJar(), loader);
        }
        Set<String> missing = new TreeSet<>(main);
        missing.removeAll(wasm);
        assertTrue(missing.isEmpty(), "public API of the main artifact missing here:\n" + String.join("\n", missing));
        Set<String> added = new TreeSet<>(wasm);
        added.removeAll(main);
        System.out.println("public API: " + main.size() + " members shared; added here: " + added);
    }

    /** Every public member of every public class of {@code PACKAGE} in {@code jar}, as a signature. */
    private static Set<String> publicApi(Path jar, ClassLoader loader) throws Exception {
        Set<String> api = new TreeSet<>();
        try (JarFile file = new JarFile(jar.toFile())) {
            Enumeration<JarEntry> entries = file.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName();
                if (!name.endsWith(".class") || !name.startsWith(PACKAGE.replace('.', '/') + "/")) {
                    continue;
                }
                String className = name.substring(0, name.length() - 6).replace('/', '.');
                if (className.substring(PACKAGE.length() + 1).contains(".")) {
                    continue; // a subpackage: internal
                }
                Class<?> type = loader.loadClass(className);
                if (!Modifier.isPublic(type.getModifiers())) {
                    continue;
                }
                api.add("type " + type.getName() + " " + Modifier.toString(type.getModifiers()));
                for (java.lang.reflect.Constructor<?> c : type.getConstructors()) {
                    api.add(c.toGenericString());
                }
                for (Method m : type.getMethods()) {
                    if (m.getDeclaringClass() == type) {
                        api.add(m.toGenericString());
                    }
                }
                for (java.lang.reflect.Field f : type.getFields()) {
                    if (f.getDeclaringClass() == type) {
                        api.add(f.toGenericString());
                    }
                }
                api.add("implements " + type.getName() + " " + Arrays.toString(type.getGenericInterfaces()));
            }
        }
        return api;
    }
}
