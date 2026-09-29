package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/**
 * The module this jar was compiled from, and whether it is the round-13
 * stand-in: the canonical-ABI module built from the 0.6 core
 * (docs/evidence/2026-09-29-canonical-abi-final), committed until the
 * release build of aprv.wasm replaces it. The 0.6 core writes 0.6's reason
 * names and payload shapes, so some cases differ; {@link #FILE} lists them.
 */
final class StandIn {

    /** The stand-in's SHA-256 ({@code aprv-cabi.core.wasm} of round 13). */
    static final String SHA256 = "da786ac853464e7b837c5483f9b04a27a3a5c2ff0340fa526f60482fd80fdb68";

    /** The case ids the stand-in answers differently, one per line; {@code #} starts a comment, on a line or after an id. */
    static final String FILE = "stand-in-differences.txt";

    private StandIn() {}

    /** The SHA-256 pinned beside the module this jar was compiled from. */
    static String moduleSha256() throws IOException {
        try (InputStream in = Verifier.class.getResourceAsStream("aprv.wasm.sha256")) {
            if (in == null) {
                throw new IllegalStateException("aprv.wasm.sha256 is not on the classpath");
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.US_ASCII));
            return reader.readLine().substring(0, 64);
        }
    }

    static boolean active() throws IOException {
        return SHA256.equals(moduleSha256());
    }

    /** The listed ids while the stand-in is the module; empty for any other module. */
    static Set<String> differences() throws IOException {
        if (!active()) {
            return Collections.emptySet();
        }
        return list(FILE);
    }

    /** The ids a stand-in list names. */
    static Set<String> list(String file) throws IOException {
        Set<String> ids = new TreeSet<>();
        try (InputStream in = StandIn.class.getResourceAsStream(file)) {
            if (in == null) {
                throw new IllegalStateException(file + " is not on the test classpath");
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                int comment = line.indexOf('#');
                line = (comment < 0 ? line : line.substring(0, comment)).trim();
                if (!line.isEmpty()) {
                    ids.add(line);
                }
            }
        }
        return ids;
    }
}
