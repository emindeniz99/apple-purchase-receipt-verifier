package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.Nullable;

/**
 * The instance model of ARCHITECTURE.md §5: a small pool of instances of one
 * compiled module. Each instance gets {@code init} once, when it is made, so
 * the roots and revocation settings are read once per instance; each serves one call at a time; an
 * instance whose call threw is discarded with everything in it, and the next
 * call takes another or makes a new one. Instances die with the pool; there
 * is nothing to close.
 *
 * <p>No call waits for another: a call that finds no idle instance makes one
 * (on Endive a few milliseconds once the classes are loaded). At most
 * {@code maxIdle} instances are kept between calls; the rest are dropped.</p>
 */
final class GuestPool {

    /**
     * One operation on an instance, and the decoding of its answer, as one
     * unit. {@code maxInputBytes} is what the instance's {@code init} answer
     * stated: the most bytes of one input to hand it.
     */
    interface Call<T> {
        T run(Guest guest, int maxInputBytes);
    }

    private final GuestFactory factory;
    private final byte[] configJson;
    private final int maxIdle;
    private final ConcurrentLinkedDeque<Guest> idle = new ConcurrentLinkedDeque<>();
    private final AtomicInteger idleCount = new AtomicInteger();
    private final AtomicInteger created = new AtomicInteger();
    /** The last {@code init} answer; null before the first. */
    private volatile @Nullable InitAnswer init;

    GuestPool(GuestFactory factory, byte[] configJson, int maxIdle) {
        this.factory = factory;
        this.configJson = configJson.clone();
        this.maxIdle = maxIdle;
    }

    /**
     * Runs {@code call} on an instance of its own. The instance goes back to
     * the pool only when {@code call} returned; any exception discards it.
     *
     * @throws GuestFailure when no instance could be made, the module refused
     *     the configuration, or {@code call} threw a runtime exception
     */
    <T> T call(Call<T> call) {
        Guest guest;
        try {
            guest = acquire();
        } catch (InitRefused e) {
            // Only reachable with the runtime probe off: create() would have
            // refused this configuration.
            throw new GuestFailure("the verifier module refused the configuration: " + e.getMessage(), e);
        }
        T result;
        try {
            result = call.run(guest, maxInputBytes());
        } catch (GuestFailure e) {
            throw e;
        } catch (RuntimeException e) {
            throw new GuestFailure("the verifier module failed: " + e, e);
        }
        release(guest);
        return result;
    }

    /**
     * Makes one instance now and keeps it for the first call: the runtime
     * probe of {@link Config#runtimeProbe()}.
     *
     * @throws InitRefused  if the module refused the configuration
     * @throws GuestFailure if the instance could not be made or {@code init}
     *     failed
     */
    void prime() {
        release(fresh());
    }

    /** How many instances this pool has made, for tests. */
    int created() {
        return created.get();
    }

    /** The {@code max_input_bytes} the module's {@code init} stated; 0 before the first instance. */
    int maxInputBytes() {
        InitAnswer answer = init;
        return answer == null ? 0 : answer.maxInputBytes;
    }

    /**
     * The module's {@code init} answer for this pool's configuration,
     * making the first instance now when none was made yet (the runtime
     * probe off) and keeping it for the next call.
     *
     * @throws InitRefused  if the module refused the configuration
     * @throws GuestFailure if the instance could not be made or {@code init}
     *     failed
     */
    InitAnswer initAnswer() {
        InitAnswer answer = init;
        if (answer != null) {
            return answer;
        }
        prime();
        return Objects.requireNonNull(init, "init");
    }

    /** How many instances are idle now, for tests. */
    int idle() {
        return idleCount.get();
    }

    private Guest acquire() {
        Guest guest = idle.pollFirst();
        if (guest != null) {
            idleCount.decrementAndGet();
            return guest;
        }
        return fresh();
    }

    private Guest fresh() {
        Guest guest = factory.newGuest();
        created.incrementAndGet();
        String answer;
        try {
            answer = guest.init(configJson);
        } catch (RuntimeException e) {
            throw new GuestFailure("the verifier module failed in init: " + e, e);
        }
        // Every instance runs the one compiled module on the one
        // configuration, so each answer states the same; the last one read
        // is kept.
        init = Wire.initAnswer(answer);
        return guest;
    }

    private void release(Guest guest) {
        if (idleCount.incrementAndGet() <= maxIdle) {
            idle.offerFirst(guest);
        } else {
            idleCount.decrementAndGet();
        }
    }
}
