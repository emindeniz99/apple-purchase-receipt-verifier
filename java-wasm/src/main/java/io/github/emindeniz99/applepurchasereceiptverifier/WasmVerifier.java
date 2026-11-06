package io.github.emindeniz99.applepurchasereceiptverifier;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
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

    private final GuestFactory factory;

    /**
     * @throws IllegalArgumentException if the probe is on and the module
     *     refuses the configuration: a root, a revocation list or issuer, or
     *     a distrust entry
     * @throws IllegalStateException if the probe is on and the module cannot
     *     be instantiated or initialised here
     */
    WasmVerifier(Config config, GuestFactory factory) {
        this.clock = config.clock();
        this.factory = factory;
        this.pool = new GuestPool(
                factory,
                InitConfig.json(config).getBytes(StandardCharsets.UTF_8),
                Math.max(2, Runtime.getRuntime().availableProcessors()));
        if (config.runtimeProbe()) {
            initAnswer();
        }
    }

    /**
     * The module's {@code init} answer, making the first instance now when
     * the probe was off.
     *
     * @throws IllegalArgumentException if the module refuses the configuration
     * @throws IllegalStateException if the module cannot be instantiated or
     *     initialised here
     */
    private InitAnswer initAnswer() {
        try {
            return pool.initAnswer();
        } catch (InitRefused e) {
            throw new IllegalArgumentException("the verifier module refused the configuration: " + e.getMessage(), e);
        } catch (GuestFailure e) {
            throw new IllegalStateException(
                    "this runtime cannot run the verifier module (" + factory.describe() + "): " + e.getMessage(), e);
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>As the module's {@code init} answered it. With the runtime probe
     * off, the first call of this method or of a verify method makes the
     * first module instance.</p>
     *
     * @throws IllegalArgumentException with the probe off, if the module
     *     refuses the configuration
     * @throws IllegalStateException with the probe off, if the module cannot
     *     run here
     */
    @Override
    public List<String> revocationUrls() {
        return initAnswer().revocationUrls;
    }

    /**
     * {@inheritDoc}
     *
     * <p>As the module's {@code init} answered it; throws as
     * {@link #revocationUrls()}.</p>
     */
    @Override
    public @Nullable Instant revocationValidUntil() {
        return initAnswer().revocationValidUntil();
    }

    /** How many module instances this verifier has made, for tests. */
    GuestPool pool() {
        return pool;
    }

    @Override
    public VerificationResult<ReceiptPayload> verifyReceipt(@Nullable String base64) {
        try {
            long now = clock.millis();
            if (now < 0) {
                return VerificationResult.failed(negativeClock());
            }
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
            if (now < 0) {
                return VerificationResult.failed(negativeClock());
            }
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
        // The WIT's env is the enum `environment`, lowered as its discriminant:
        // the module reads its low 8 bits, 0 production and 1 sandbox, and
        // traps on any other low byte. Environment keeps it on 0 or 1.
        int env = environment == Environment.PRODUCTION ? 0 : 1;
        try {
            long now = clock.millis();
            if (now < 0) {
                return "{\"status\":" + AppleStatus.INTERNAL_DATA_ACCESS_ERROR + "}";
            }
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

    /**
     * A clock before 1970, refused before the module is called, as every other
     * package refuses it. The WIT's {@code now-ms} has been an {@code s64}
     * since ABI 0.2.0 and would carry the instant to the core; under 0.1.0 a
     * {@code u64} could not, and the module answered INTERNAL_ERROR. Both
     * engines keep that answer (DECISIONS.md R46).
     */
    static Failure negativeClock() {
        return new Failure(Reason.INTERNAL_ERROR, "the configured clock answered a negative time", null);
    }

    /** As the main artifact words it: a clock that threw, or a defect here. */
    private static Failure internalError(RuntimeException e) {
        return new Failure(Reason.INTERNAL_ERROR, "unexpected " + e.getClass().getName(), e);
    }
}
