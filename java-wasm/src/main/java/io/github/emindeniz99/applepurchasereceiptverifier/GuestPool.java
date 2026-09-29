package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The instance model of ARCHITECTURE.md §5: a small pool of instances of one
 * compiled module. Each instance gets {@code init} once, when it is made, so
 * the roots are parsed once per instance; each serves one call at a time; an
 * instance whose call threw is discarded with everything in it, and the next
 * call takes another or makes a new one. Instances die with the pool; there
 * is nothing to close.
 *
 * <p>No call waits for another: a call that finds no idle instance makes one
 * (on Endive a few milliseconds once the classes are loaded). At most
 * {@code maxIdle} instances are kept between calls; the rest are dropped.</p>
 */
final class GuestPool {

    /** One operation on an instance, and the decoding of its answer, as one unit. */
    interface Call<T> {
        T run(Guest guest);
    }

    private final GuestFactory factory;
    private final byte[] configJson;
    private final int maxIdle;
    private final ConcurrentLinkedDeque<Guest> idle = new ConcurrentLinkedDeque<>();
    private final AtomicInteger idleCount = new AtomicInteger();
    private final AtomicInteger created = new AtomicInteger();

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
            throw new GuestFailure("the verifier module refused the configured roots: " + e.getMessage(), e);
        }
        T result;
        try {
            result = call.run(guest);
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
        Wire.initAnswer(answer);
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
