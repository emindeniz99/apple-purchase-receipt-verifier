package io.github.emindeniz99.applepurchasereceiptverifier;

import io.github.emindeniz99.applepurchasereceiptverifier.endive.AprvModule;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * The Endive engine's {@link GuestFactory}. {@link Engine.Endive} loads this
 * Java 11 class by name, only after it has checked the JVM is Java 11 or
 * later. Constructing it loads and parses the compiled module once per JVM
 * (the first instance takes a few hundred milliseconds; later ones a few).
 */
final class EndiveGuestFactory implements GuestFactory {

    /** The module's SHA-256, written into the jar beside the compiled classes at build time. */
    static final String MODULE_SHA256_RESOURCE = "aprv.wasm.sha256";

    private final SecureRandom random = new SecureRandom();
    private final String description;

    EndiveGuestFactory() {
        // Parses the stripped module (data segments, types, exports) once; a
        // jar without the compiled module fails here, at create.
        AprvModule.load();
        this.description = "Endive, aprv.wasm sha256 " + moduleSha256();
    }

    @Override
    public Guest newGuest() {
        return new EndiveGuest(random);
    }

    @Override
    public String describe() {
        return description;
    }

    /** The first 64 characters of the pinned hash file, or "unknown". */
    static String moduleSha256() {
        try (InputStream in = EndiveGuestFactory.class.getResourceAsStream(MODULE_SHA256_RESOURCE)) {
            if (in == null) {
                return "unknown";
            }
            byte[] head = new byte[64];
            int n = 0;
            int r;
            while (n < head.length && (r = in.read(head, n, head.length - n)) > 0) {
                n += r;
            }
            return new String(head, 0, n, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            return "unknown";
        }
    }
}
