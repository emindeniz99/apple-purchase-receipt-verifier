package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.JarURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * What the class files prove, read from the bytes rather than trusted from
 * the build: the facade, the engine API and the server client are Java 8
 * (major 52) and only the Endive engine and its generated classes are
 * Java 11 (major 55); and nothing on the consumer's classpath (this
 * artifact's classes, Endive's runtime and wasm jars, jackson-core) loads
 * native code: no native method, no {@code System.load}/{@code loadLibrary},
 * no {@code Runtime.load}, no FFM, no {@code Unsafe}, no JNA or jffi.
 */
class ClassFileTest {

    private static final Path CLASSES = Paths.get("target", "classes");

    /** Java 11 bytecode: the Endive engine (src/main/java11) and what Endive generated. */
    private static boolean endive(String name) {
        return name.startsWith("io/github/emindeniz99/applepurchasereceiptverifier/endive/")
                || name.startsWith("io/github/emindeniz99/applepurchasereceiptverifier/EndiveGuest");
    }

    @Test
    void theFacadeIsJava8AndOnlyTheEndiveEngineIsJava11() throws Exception {
        Map<String, Integer> majors = new TreeMap<>();
        try (Stream<Path> walk = Files.walk(CLASSES)) {
            for (Path file : walk.filter(p -> p.toString().endsWith(".class")).collect(Collectors.toList())) {
                String name = CLASSES.relativize(file).toString().replace('\\', '/');
                majors.put(name, classFile(Files.readAllBytes(file)).major);
            }
        }
        int java8 = 0;
        int java11 = 0;
        for (Map.Entry<String, Integer> entry : majors.entrySet()) {
            int want = endive(entry.getKey()) ? 55 : 52;
            assertEquals(want, entry.getValue().intValue(), entry.getKey());
            if (want == 52) {
                java8++;
            } else {
                java11++;
            }
        }
        assertTrue(majors.containsKey("io/github/emindeniz99/applepurchasereceiptverifier/Verifier.class"));
        assertTrue(majors.containsKey("io/github/emindeniz99/applepurchasereceiptverifier/EndiveGuest.class"));
        assertTrue(majors.containsKey("io/github/emindeniz99/applepurchasereceiptverifier/endive/AprvModule.class"));
        System.out.println("class files: " + java8 + " at major 52 (Java 8), " + java11 + " at major 55 (Java 11)");
    }

    @Test
    void nothingOnTheConsumerClasspathLoadsNativeCode() throws Exception {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        try (Stream<Path> walk = Files.walk(CLASSES)) {
            for (Path file : walk.filter(p -> p.toString().endsWith(".class")).collect(Collectors.toList())) {
                classes.put("target/classes/" + CLASSES.relativize(file), Files.readAllBytes(file));
            }
        }
        List<String> jars = new ArrayList<>();
        for (String probe : new String[] {
            "run/endive/runtime/Instance.class",
            "run/endive/wasm/WasmModule.class",
            "com/fasterxml/jackson/core/JsonParser.class"
        }) {
            URL url = ClassFileTest.class.getClassLoader().getResource(probe);
            assertTrue(url != null && "jar".equals(url.getProtocol()), probe + " is in a jar: " + url);
            JarURLConnection connection = (JarURLConnection) url.openConnection();
            connection.setUseCaches(false);
            String jar = connection.getJarFileURL().getPath();
            jars.add(jar.substring(jar.lastIndexOf('/') + 1));
            try (JarFile file =
                    new JarFile(Paths.get(connection.getJarFileURL().toURI()).toFile())) {
                Enumeration<JarEntry> entries = file.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (entry.getName().endsWith(".class")) {
                        try (InputStream in = file.getInputStream(entry)) {
                            classes.put(jar + "!" + entry.getName(), read(in));
                        }
                    }
                    assertTrue(!nativeLibrary(entry.getName()), "a native library in " + jar + ": " + entry.getName());
                }
            }
        }
        List<String> findings = new ArrayList<>();
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            for (String finding : classFile(entry.getValue()).nativeUse) {
                findings.add(entry.getKey() + ": " + finding);
            }
        }
        assertTrue(findings.isEmpty(), String.join("\n", findings));
        System.out.println("native check: " + classes.size() + " classes (target/classes, " + String.join(", ", jars)
                + "), 0 native methods, 0 native-loading references");
    }

    private static boolean nativeLibrary(String name) {
        String lower = name.toLowerCase(java.util.Locale.ROOT);
        return lower.endsWith(".so") || lower.endsWith(".dll") || lower.endsWith(".dylib") || lower.endsWith(".jnilib");
    }

    private static byte[] read(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[65536];
        int n;
        while ((n = in.read(buffer)) > 0) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }

    // ------------------------------------------------------------ class files

    private static final class ClassFileFacts {
        int major;
        final List<String> nativeUse = new ArrayList<>();
    }

    private static final String[] FORBIDDEN_TYPES = {
        "java/lang/foreign/",
        "jdk/internal/foreign/",
        "sun/misc/Unsafe",
        "jdk/internal/misc/Unsafe",
        "com/sun/jna/",
        "com/kenai/jffi/",
        "jnr/ffi/"
    };

    /** The constant pool and the methods' flags of one class file (JVMS 4). */
    private static ClassFileFacts classFile(byte[] bytes) throws IOException {
        ClassFileFacts facts = new ClassFileFacts();
        DataInputStream in = new DataInputStream(new java.io.ByteArrayInputStream(bytes));
        if (in.readInt() != 0xCAFEBABE) {
            throw new IOException("not a class file");
        }
        in.readUnsignedShort();
        facts.major = in.readUnsignedShort();
        int count = in.readUnsignedShort();
        String[] utf8 = new String[count];
        int[] classNames = new int[count];
        int[][] refs = new int[count][];
        int[][] nameAndTypes = new int[count][];
        for (int i = 1; i < count; i++) {
            int tag = in.readUnsignedByte();
            switch (tag) {
                case 1:
                    utf8[i] = in.readUTF();
                    break;
                case 3:
                case 4:
                    in.readInt();
                    break;
                case 5:
                case 6:
                    in.readLong();
                    i++;
                    break;
                case 7:
                    classNames[i] = in.readUnsignedShort();
                    break;
                case 8:
                case 16:
                case 19:
                case 20:
                    in.readUnsignedShort();
                    break;
                case 9:
                case 10:
                case 11:
                    refs[i] = new int[] {in.readUnsignedShort(), in.readUnsignedShort()};
                    break;
                case 12:
                    nameAndTypes[i] = new int[] {in.readUnsignedShort(), in.readUnsignedShort()};
                    break;
                case 15:
                    in.readUnsignedByte();
                    in.readUnsignedShort();
                    break;
                case 17:
                case 18:
                    in.readInt();
                    break;
                default:
                    throw new IOException("constant pool tag " + tag);
            }
        }
        for (int i = 1; i < count; i++) {
            if (utf8[i] != null) {
                for (String forbidden : FORBIDDEN_TYPES) {
                    if (utf8[i].contains(forbidden)) {
                        facts.nativeUse.add("references " + utf8[i]);
                    }
                }
            }
            if (refs[i] != null) {
                String owner = utf8[classNames[refs[i][0]]];
                String name = utf8[nameAndTypes[refs[i][1]][0]];
                if (("java/lang/System".equals(owner) || "java/lang/Runtime".equals(owner))
                        && ("load".equals(name) || "loadLibrary".equals(name))) {
                    facts.nativeUse.add("calls " + owner + "." + name);
                }
            }
        }
        in.readUnsignedShort(); // access flags
        in.readUnsignedShort(); // this
        in.readUnsignedShort(); // super
        int interfaces = in.readUnsignedShort();
        for (int i = 0; i < interfaces; i++) {
            in.readUnsignedShort();
        }
        skipMembers(in, null);
        skipMembers(in, facts);
        return facts;
    }

    /** Fields, or methods when {@code facts} is given: a native method is a finding. */
    private static void skipMembers(DataInputStream in, ClassFileFacts facts) throws IOException {
        int members = in.readUnsignedShort();
        for (int i = 0; i < members; i++) {
            int flags = in.readUnsignedShort();
            in.readUnsignedShort();
            in.readUnsignedShort();
            if (facts != null && (flags & 0x0100) != 0) {
                facts.nativeUse.add("declares a native method");
            }
            int attributes = in.readUnsignedShort();
            for (int a = 0; a < attributes; a++) {
                in.readUnsignedShort();
                long length = in.readInt() & 0xffffffffL;
                in.skipBytes((int) length);
            }
        }
    }
}
