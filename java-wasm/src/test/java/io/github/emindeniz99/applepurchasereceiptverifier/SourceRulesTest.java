package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Rules on this artifact's own sources (R25, THREAT-MODEL.md §7): nothing
 * outside the program chooses the engine or points it at a binary, so no
 * source reads a system property or an environment variable, and none loads
 * native code.
 */
class SourceRulesTest {

    private static final Pattern CONFIGURATION_FROM_OUTSIDE =
            Pattern.compile("System\\s*\\.\\s*(getProperty|getProperties|getenv|setProperty)\\b"
                    + "|\\b(Integer\\s*\\.\\s*getInteger|Long\\s*\\.\\s*getLong|Boolean\\s*\\.\\s*getBoolean)\\s*\\(");

    private static final Pattern NATIVE_LOADING = Pattern.compile(
            "System\\s*\\.\\s*(load|loadLibrary)\\s*\\(|Runtime\\s*\\.\\s*getRuntime\\s*\\(\\s*\\)\\s*\\.\\s*load"
                    + "|\\bnative\\s+[\\w<>\\[\\]]+\\s+\\w+\\s*\\(|java\\.lang\\.foreign|sun\\.misc\\.Unsafe|com\\.sun\\.jna");

    private static List<Path> sources() throws Exception {
        List<Path> files = new ArrayList<>();
        for (String root : new String[] {"src/main/java", "src/main/java11"}) {
            try (Stream<Path> walk = Files.walk(Paths.get(root))) {
                files.addAll(walk.filter(p -> p.toString().endsWith(".java")).collect(Collectors.toList()));
            }
        }
        assertTrue(files.size() > 10, "found the sources: " + files);
        return files;
    }

    private static List<String> matches(Pattern pattern) throws Exception {
        List<String> hits = new ArrayList<>();
        for (Path file : sources()) {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
            for (int i = 0; i < lines.size(); i++) {
                Matcher matcher = pattern.matcher(lines.get(i));
                if (matcher.find()) {
                    hits.add(file + ":" + (i + 1) + ": " + lines.get(i).trim());
                }
            }
        }
        return hits;
    }

    /**
     * The JDK's own facts about the machine, which the server engine needs to
     * pick a binary and a cache directory. They configure nothing of ours.
     */
    private static final Pattern THE_JDKS_OWN = Pattern.compile(
            "^[^:]*Platform\\.java:\\d+: .*System\\.getProperty\\(\"(os\\.name|os\\.arch|user\\.home)\"");

    @Test
    void noSourceReadsASystemPropertyOrAnEnvironmentVariable() throws Exception {
        List<String> hits = new ArrayList<>();
        int platform = 0;
        for (String hit : matches(CONFIGURATION_FROM_OUTSIDE)) {
            if (THE_JDKS_OWN.matcher(hit).find()) {
                platform++;
            } else {
                hits.add(hit);
            }
        }
        assertTrue(hits.isEmpty(), String.join("\n", hits));
        assertTrue(platform == 3, "Platform reads os.name, os.arch and user.home, and nothing else: " + platform);
    }

    @Test
    void noSourceLoadsNativeCode() throws Exception {
        List<String> hits = matches(NATIVE_LOADING);
        assertTrue(hits.isEmpty(), String.join("\n", hits));
    }

    /** The patterns find what they are meant to, so an empty result means something. */
    @Test
    void thePatternsMatchWhatTheyForbid() {
        assertTrue(CONFIGURATION_FROM_OUTSIDE
                .matcher("x = System.getProperty(\"a\");")
                .find());
        assertTrue(CONFIGURATION_FROM_OUTSIDE.matcher("System.getenv(\"A\")").find());
        assertTrue(
                CONFIGURATION_FROM_OUTSIDE.matcher("Boolean.getBoolean(\"a\")").find());
        assertTrue(NATIVE_LOADING.matcher("System.loadLibrary(\"x\");").find());
        assertTrue(NATIVE_LOADING.matcher("private static native int f(int a);").find());
    }
}
