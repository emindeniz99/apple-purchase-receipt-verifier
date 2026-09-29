package aprvj.nativeimage;

import aprvj.Bridge;
import java.nio.charset.StandardCharsets;
import org.graalvm.nativeimage.Isolate;
import org.graalvm.nativeimage.IsolateThread;
import org.graalvm.nativeimage.ObjectHandle;
import org.graalvm.nativeimage.ObjectHandles;
import org.graalvm.nativeimage.UnmanagedMemory;
import org.graalvm.nativeimage.c.function.CEntryPoint;
import org.graalvm.nativeimage.c.type.CCharPointer;
import org.graalvm.nativeimage.c.type.CCharPointerPointer;
import org.graalvm.nativeimage.c.type.CTypeConversion;
import org.graalvm.word.UnsignedWord;
import org.graalvm.word.WordFactory;

/**
 * The C ABI shims. Each one converts C arguments to Java values, calls
 * {@link Bridge}, and copies the answer into malloc'd memory. Nothing here
 * decides a verdict.
 *
 * <p>Lifecycle (explicit, no process-global isolate):
 * <pre>
 *   graal_isolatethread_t *t = aprvj_runtime_new();      // creates an isolate, attaches this thread
 *   graal_isolate_t *iso     = aprvj_runtime_isolate(t); // for other threads
 *   graal_isolatethread_t *t2 = aprvj_thread_attach(iso);  // on another OS thread
 *   ... aprvj_* calls, each passing the calling thread's own t / t2 ...
 *   aprvj_thread_detach(t2);                               // on that thread, before it exits
 *   aprvj_runtime_free(t);                                 // tears the isolate down
 * </pre>
 *
 * <p>Memory: every {@code char*} the ABI hands out was allocated with
 * {@link UnmanagedMemory#malloc}, which is the C library's malloc on Linux,
 * and is released with exactly one {@code aprvj_string_free}. No pointer into
 * the Java heap is ever returned.
 */
public final class NativeEntryPoints {

    private NativeEntryPoints() {}

    // ------------------------------------------------------------- lifecycle

    @CEntryPoint(name = "aprvj_runtime_new", builtin = CEntryPoint.Builtin.CREATE_ISOLATE,
            documentation = "Create a runtime (a Native Image isolate) and attach the calling thread. NULL on failure.")
    static native IsolateThread runtimeNew();

    @CEntryPoint(name = "aprvj_runtime_isolate", builtin = CEntryPoint.Builtin.GET_ISOLATE,
            documentation = "The isolate a thread belongs to, for aprvj_thread_attach on another OS thread.")
    static native Isolate runtimeIsolate(IsolateThread thread);

    @CEntryPoint(name = "aprvj_thread_attach", builtin = CEntryPoint.Builtin.ATTACH_THREAD,
            documentation = "Attach the calling OS thread to the runtime. Each OS thread uses only its own handle.")
    static native IsolateThread threadAttach(Isolate isolate);

    @CEntryPoint(name = "aprvj_thread_detach", builtin = CEntryPoint.Builtin.DETACH_THREAD,
            documentation = "Detach the calling OS thread. Call on that thread, before it exits.")
    static native int threadDetach(IsolateThread thread);

    @CEntryPoint(name = "aprvj_runtime_free", builtin = CEntryPoint.Builtin.TEAR_DOWN_ISOLATE,
            documentation = "Tear the runtime down. Every other thread must have detached first.")
    static native int runtimeFree(IsolateThread thread);

    // ------------------------------------------------------------- exceptions
    //
    // No custom CEntryPoint exceptionHandler: the public API accepts one only
    // if its method carries com.oracle.svm.core.Uninterruptible, an internal
    // builder annotation (the build fails without it). So every shim catches
    // Throwable itself and turns it into a code. A Throwable escaping that
    // catch (for example an OutOfMemoryError while building the error JSON)
    // reaches the default FatalExceptionHandler, which ends the process.

    // ------------------------------------------------------------- handles

    @CEntryPoint(name = "aprvj_receipt_verifier_new",
            documentation = "ReceiptVerifier from options JSON {bundleId, roots?}. NULL on failure; *error gets a malloc'd JSON reason if error is not NULL.")
    static ObjectHandle receiptVerifierNew(IsolateThread thread, CCharPointer optionsJson, CCharPointerPointer error) {
        try {
            return ObjectHandles.getGlobal().create(Bridge.newReceiptVerifier(cString(optionsJson)));
        } catch (Throwable t) {
            put(error, Bridge.failure(t).json);
            return WordFactory.zero();
        }
    }

    @CEntryPoint(name = "aprvj_jws_verifier_new",
            documentation = "JwsVerifier from options JSON {bundleId, acceptedEnvironments, appAppleId?, roots?}.")
    static ObjectHandle jwsVerifierNew(IsolateThread thread, CCharPointer optionsJson, CCharPointerPointer error) {
        try {
            return ObjectHandles.getGlobal().create(Bridge.newJwsVerifier(cString(optionsJson)));
        } catch (Throwable t) {
            put(error, Bridge.failure(t).json);
            return WordFactory.zero();
        }
    }

    @CEntryPoint(name = "aprvj_endpoint_new",
            documentation = "VerifyReceiptEndpoint from options JSON {environment, roots?, nowMillis?}.")
    static ObjectHandle endpointNew(IsolateThread thread, CCharPointer optionsJson, CCharPointerPointer error) {
        try {
            return ObjectHandles.getGlobal().create(Bridge.newEndpoint(cString(optionsJson)));
        } catch (Throwable t) {
            put(error, Bridge.failure(t).json);
            return WordFactory.zero();
        }
    }

    @CEntryPoint(name = "aprvj_handle_free",
            documentation = "Release a verifier or endpoint handle. NULL is ignored. A handle must be freed once.")
    static void handleFree(IsolateThread thread, ObjectHandle handle) {
        try {
            if (handle.notEqual(WordFactory.zero())) {
                ObjectHandles.getGlobal().destroy(handle);
            }
        } catch (Throwable ignored) {
            // A handle that is not live: nothing to release.
        }
    }

    // ------------------------------------------------------------- calls

    @CEntryPoint(name = "aprvj_verify_receipt",
            documentation = "Verify a receipt: DER bytes, or base64 text when is_base64 != 0; device_guid may be NULL. Returns 0 or a reason/ABI code; *out gets malloc'd JSON.")
    static int verifyReceipt(IsolateThread thread, ObjectHandle verifier, CCharPointer bytes, UnsignedWord length,
            int isBase64, CCharPointer deviceGuid, UnsignedWord deviceGuidLength, CCharPointerPointer out) {
        Bridge.Result result;
        try {
            byte[] input = bytes(bytes, length, "receipt");
            byte[] guid = deviceGuid.isNull() ? null : bytes(deviceGuid, deviceGuidLength, "device_guid");
            result = Bridge.verifyReceipt(object(verifier), input, isBase64 != 0, guid);
        } catch (Throwable t) {
            result = Bridge.failure(t);
        }
        put(out, result.json);
        return result.code;
    }

    @CEntryPoint(name = "aprvj_verify_jws",
            documentation = "Verify a JWS of length bytes (UTF-8). operation: 0 transaction, 1 app transaction, 2 raw claims.")
    static int verifyJws(IsolateThread thread, ObjectHandle verifier, CCharPointer jws, UnsignedWord length,
            int operation, CCharPointerPointer out) {
        Bridge.Result result;
        try {
            result = Bridge.verifyJws(object(verifier), utf8(jws, length, "jws"), operation);
        } catch (Throwable t) {
            result = Bridge.failure(t);
        }
        put(out, result.json);
        return result.code;
    }

    @CEntryPoint(name = "aprvj_verify_receipt_json",
            documentation = "Apple verifyReceipt-compatible call: request JSON in, Apple response JSON in *out. Returns the failureReason code, 0 when there is none.")
    static int verifyReceiptJson(IsolateThread thread, ObjectHandle endpoint, CCharPointer request, UnsignedWord length,
            CCharPointerPointer out) {
        Bridge.Result result;
        try {
            result = Bridge.verifyReceiptJson(object(endpoint), utf8(request, length, "request"));
        } catch (Throwable t) {
            result = Bridge.failure(t);
        }
        put(out, result.json);
        return result.code;
    }

    @CEntryPoint(name = "aprvj_self_check",
            documentation = "Load and pin the bundled Apple roots; *out gets their SHA-256s, or the error.")
    static int selfCheck(IsolateThread thread, CCharPointerPointer out) {
        Bridge.Result result;
        try {
            result = Bridge.selfCheck();
        } catch (Throwable t) {
            result = Bridge.failure(t);
        }
        put(out, result.json);
        return result.code;
    }

    @CEntryPoint(name = "aprvj_string_free",
            documentation = "Free a string this library returned. NULL is ignored. Any attached thread may free it.")
    static void stringFree(IsolateThread thread, CCharPointer string) {
        if (string.isNonNull()) {
            UnmanagedMemory.free(string);
        }
    }

    // ------------------------------------------------------------- marshalling

    private static Object object(ObjectHandle handle) {
        if (handle.equal(WordFactory.zero())) {
            throw new IllegalArgumentException("handle is NULL");
        }
        return ObjectHandles.getGlobal().get(handle);
    }

    private static String cString(CCharPointer pointer) {
        return pointer.isNull() ? null : CTypeConversion.toJavaString(pointer, lengthOf(pointer), StandardCharsets.UTF_8);
    }

    private static UnsignedWord lengthOf(CCharPointer pointer) {
        long n = 0;
        while (pointer.read((int) n) != 0) {
            n++;
            if (n >= Integer.MAX_VALUE) {
                throw new IllegalArgumentException("string not terminated");
            }
        }
        return WordFactory.unsigned(n);
    }

    private static byte[] bytes(CCharPointer pointer, UnsignedWord length, String what) {
        long n = length.rawValue();
        if (n < 0 || n > Integer.MAX_VALUE - 8) {
            throw new IllegalArgumentException(what + " length out of range");
        }
        if (pointer.isNull()) {
            if (n != 0) {
                throw new IllegalArgumentException(what + " is NULL with a non-zero length");
            }
            return new byte[0];
        }
        byte[] out = new byte[(int) n];
        CTypeConversion.asByteBuffer(pointer, (int) n).get(out);
        return out;
    }

    private static String utf8(CCharPointer pointer, UnsignedWord length, String what) {
        if (pointer.isNull() && length.rawValue() == 0) {
            return null; // a NULL input is the library's own "null" verdict, as on the JVM
        }
        return new String(bytes(pointer, length, what), StandardCharsets.UTF_8);
    }

    /** Copies {@code text} as NUL-terminated UTF-8 into malloc'd memory at *out. */
    private static void put(CCharPointerPointer out, String text) {
        if (out.isNull()) {
            return;
        }
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        CCharPointer copy = UnmanagedMemory.malloc(data.length + 1);
        if (copy.isNull()) {
            out.write(WordFactory.nullPointer()); // out of C memory: the code still says what happened
            return;
        }
        CTypeConversion.asByteBuffer(copy, data.length).put(data);
        copy.write(data.length, (byte) 0);
        out.write(copy);
    }
}
