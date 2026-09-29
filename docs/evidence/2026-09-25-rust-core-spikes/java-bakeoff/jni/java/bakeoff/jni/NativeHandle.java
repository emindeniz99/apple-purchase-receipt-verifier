package bakeoff.jni;

import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Owns one native handle. Calls hold the read lock, so any number run in
 * parallel; close() takes the write lock, so it waits for them and no call
 * can see a freed handle.
 */
abstract class NativeHandle implements AutoCloseable {
    interface Call<T, E extends Exception> { T apply(long handle) throws E; }

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private long handle;

    NativeHandle(long handle) { this.handle = handle; }

    abstract void free(long handle);

    final <T, E extends Exception> T call(Call<T, E> c) throws E {
        ReentrantReadWriteLock.ReadLock r = lock.readLock();
        r.lock();
        try {
            if (handle == 0) throw new IllegalStateException(getClass().getSimpleName() + " is closed");
            return c.apply(handle);
        } finally {
            r.unlock();
        }
    }

    /** Frees the native object. Idempotent. */
    @Override
    public void close() {
        ReentrantReadWriteLock.WriteLock w = lock.writeLock();
        w.lock();
        try {
            if (handle != 0) {
                free(handle);
                handle = 0;
            }
        } finally {
            w.unlock();
        }
    }
}
