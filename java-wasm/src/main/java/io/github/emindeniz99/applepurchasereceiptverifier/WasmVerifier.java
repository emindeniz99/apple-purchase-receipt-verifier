package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * The {@link Verifier} over the verifier module. It reads the clock, moves
 * the input in and the answer out, and maps the outcome; every verification
 * decision is the module's.
 *
 * <p>Each method reads the clock once, before the input is touched, and
 * passes it as {@code now-ms}; a clock that throws is
 * {@link Reason#INTERNAL_ERROR} (21009 from the endpoint), as in the main
 * artifact. A module failure of any kind (a trap, a runtime error, an answer
 * this class cannot read) is {@link Reason#INTERNAL_ERROR} with the
 * {@link GuestFailure} as the cause; the pool has discarded the instance.</p>
 */
final class WasmVerifier implements Verifier {

    private final Clock clock;
    private final GuestPool pool;

    /**
     * @throws IllegalArgumentException if the probe is on and the module
     *     refuses one of the roots
     * @throws IllegalStateException if the probe is on and the module cannot
     *     be instantiated or initialised here
     */
    WasmVerifier(Config config, GuestFactory factory) {
        this.clock = config.clock();
        this.pool = new GuestPool(
                factory,
                configJson(config.roots()),
                Math.max(2, Runtime.getRuntime().availableProcessors()));
        if (config.runtimeProbe()) {
            try {
                pool.prime();
            } catch (InitRefused e) {
                throw new IllegalArgumentException(
                        "the verifier module refused a root in the config: " + e.getMessage(), e);
            } catch (GuestFailure e) {
                throw new IllegalStateException(
                        "this runtime cannot run the verifier module (" + factory.describe() + "): " + e.getMessage(),
                        e);
            }
        }
    }

    /**
     * {@code init}'s configuration: {@code {"roots":[]}}, the module's
     * built-in Apple roots, when {@code roots} are exactly the bundled three
     * ({@link Config#defaults()}); otherwise each root's DER as padded
     * standard base64, in the config's order.
     */
    static byte[] configJson(Set<X509Certificate> roots) {
        StringBuilder json = new StringBuilder("{\"roots\":[");
        if (!roots.equals(AppleRootCerts.roots())) {
            String separator = "";
            for (X509Certificate root : roots) {
                byte[] der;
                try {
                    der = root.getEncoded();
                } catch (CertificateEncodingException e) {
                    throw new IllegalArgumentException("a root in the config cannot be encoded: " + e.getMessage(), e);
                }
                json.append(separator)
                        .append('"')
                        .append(Base64.getEncoder().encodeToString(der))
                        .append('"');
                separator = ",";
            }
        }
        return json.append("]}").toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** How many module instances this verifier has made, for tests. */
    GuestPool pool() {
        return pool;
    }

    @Override
    public VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64) {
        try {
            long now = clock.millis();
            return pool.call((guest, max) -> Wire.receiptAnswer(guest.verifyReceipt(now, bytes(base64, max))));
        } catch (GuestFailure e) {
            return VerificationResult.failed(moduleFailure(e));
        } catch (RuntimeException e) {
            return VerificationResult.failed(internalError(e));
        }
    }

    @Override
    public VerificationResult<JsonPayload> verifySignedData(@Nullable String jws) {
        try {
            long now = clock.millis();
            return pool.call((guest, max) -> Wire.signedDataAnswer(guest.verifySignedData(now, bytes(jws, max))));
        } catch (GuestFailure e) {
            return VerificationResult.failed(moduleFailure(e));
        } catch (RuntimeException e) {
            return VerificationResult.failed(internalError(e));
        }
    }

    @Override
    public String verifyReceiptEndpoint(Environment environment, @Nullable String requestJson) {
        Objects.requireNonNull(environment, "environment");
        // The WIT's env is a u32 the module matches: 0 production, 1 sandbox,
        // and a trap for anything else. Environment keeps it on 0 or 1.
        int env = environment == Environment.PRODUCTION ? 0 : 1;
        try {
            long now = clock.millis();
            // Apple's response JSON, byte for byte as the module wrote it.
            return pool.call((guest, max) ->
                    Wire.endpointAnswer(guest.verifyReceiptEndpoint(env, now, bytes(requestJson, max))));
        } catch (RuntimeException e) {
            return "{\"status\":" + AppleStatus.INTERNAL_DATA_ACCESS_ERROR + "}";
        }
    }

    /**
     * The input's UTF-8 bytes, or its first {@code maxInputBytes} of them:
     * the length the module's {@code init} answer states (DECISIONS.md R42),
     * one over the core's largest cap, so an input over it still reaches the
     * core over it and the core itself answers TOO_LARGE (21002 from the
     * endpoint), as it does for the whole input. Copying all of a larger
     * input would grow the instance's linear memory to the input's size for
     * the instance's life, and past about 2 GiB trap as INTERNAL_ERROR
     * instead. {@code null} is the empty input, which the module answers as
     * malformed. Only what is kept is encoded, so a huge input costs no huge
     * array either. Lone surrogates become {@code ?}, as
     * {@link String#getBytes} makes them.
     */
    static byte[] bytes(@Nullable String text, int maxInputBytes) {
        if (text == null) {
            return new byte[0];
        }
        if (text.length() <= maxInputBytes / 3) {
            return text.getBytes(StandardCharsets.UTF_8); // at most 3 bytes per char: under the limit
        }
        // Room for one more character, so a stop at a character boundary is
        // never short of the limit.
        ByteBuffer out = ByteBuffer.allocate(maxInputBytes + 3);
        StandardCharsets.UTF_8
                .newEncoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE)
                .encode(CharBuffer.wrap(text), out, true);
        return Arrays.copyOf(out.array(), Math.min(out.position(), maxInputBytes));
    }

    private static Failure moduleFailure(GuestFailure e) {
        return new Failure(Reason.INTERNAL_ERROR, e.getMessage(), e);
    }

    /** As the main artifact words it: a clock that threw, or a defect here. */
    private static Failure internalError(RuntimeException e) {
        return new Failure(Reason.INTERNAL_ERROR, "unexpected " + e.getClass().getName(), e);
    }
}
