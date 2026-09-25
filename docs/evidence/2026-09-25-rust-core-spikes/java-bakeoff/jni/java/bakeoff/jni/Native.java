package bakeoff.jni;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** The native methods and the decoder for their byte[] records. Internal. */
final class Native {
    private Native() {}

    static {
        String path = System.getProperty("bakeoff.jni.lib");
        if (path != null) System.load(path); else System.loadLibrary("aprv_jni");
    }

    static native long rvNew(String bundleId, byte[][] roots);
    static native void rvFree(long h);
    static native byte[] rvVerify(long h, byte[] der) throws VerificationException;
    static native byte[] rvVerifyBase64(long h, String b64) throws VerificationException;

    static native long jvNew(String bundleId, int envMask, boolean hasAppId, long appId, byte[][] roots);
    static native void jvFree(long h);
    static native byte[] jvVerifyTransaction(long h, String jws) throws VerificationException;

    static native long epNew(int environment);
    static native void epFree(long h);
    static native String epVerifyJson(long h, String body);
    static native long epVerifyResult(long h, String body);

    static native void resFree(long h);
    static native long resStatus(long h);
    static native boolean resVerified(long h);
    static native byte[] resReceipt(long h);
    static native String resFailureReason(long h);
    static native String resToJson(long h);
    static native String resToJsonIn(long h, int environment);

    static byte[][] roots(List<byte[]> roots) {
        return roots == null ? null : roots.toArray(new byte[0][]);
    }

    /** Mirrors {@code Enc} in lib.rs: presence byte, then u32 length + bytes or i64, big-endian. */
    private static final class Reader {
        private final DataInputStream in;
        Reader(byte[] b) { in = new DataInputStream(new ByteArrayInputStream(b)); }

        byte[] bytes() throws IOException {
            if (in.readByte() == 0) return null;
            byte[] b = new byte[in.readInt()];
            in.readFully(b);
            return b;
        }
        String str() throws IOException {
            byte[] b = bytes();
            return b == null ? null : new String(b, StandardCharsets.UTF_8);
        }
        Long lng() throws IOException { return in.readByte() == 0 ? null : in.readLong(); }
        int count() throws IOException { return in.readInt(); }
    }

    static AppReceipt receipt(byte[] b) {
        try {
            Reader r = new Reader(b);
            String type = r.str(), bundle = r.str(), ver = r.str(), orig = r.str();
            byte[] opaque = r.bytes(), sha1 = r.bytes();
            Long created = r.lng();
            int n = r.count();
            List<InAppPurchase> iaps = new ArrayList<>(n);
            for (int i = 0; i < n; i++) {
                iaps.add(new InAppPurchase(r.str(), r.str(), r.str(), r.lng(), r.lng(), r.lng()));
            }
            return new AppReceipt(type, bundle, ver, orig, opaque, sha1, created, Collections.unmodifiableList(iaps));
        } catch (IOException e) {
            throw new IllegalStateException("corrupt native record", e);
        }
    }

    static TransactionPayload payload(byte[] b) {
        try {
            Reader r = new Reader(b);
            return new TransactionPayload(r.str(), r.str(), r.str(), r.str(), r.lng(), r.lng(), r.str());
        } catch (IOException e) {
            throw new IllegalStateException("corrupt native record", e);
        }
    }
}
