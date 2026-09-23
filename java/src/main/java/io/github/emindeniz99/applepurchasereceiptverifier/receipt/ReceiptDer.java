package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.Exceptions;

/**
 * BouncyCastle's {@link ASN1Primitive#fromByteArray} without its one
 * avoidable cost.
 *
 * <p>{@code fromByteArray} reads through a {@link ByteArrayInputStream},
 * whose {@code read()} is {@code synchronized}, and BouncyCastle reads every
 * tag and length byte one call at a time, through one stream per nesting
 * level. A legacy receipt payload is several thousand small attributes, so
 * those uncontended monitor enters were a measurable share of parsing it. The
 * stream here is the same class with the same buffer semantics, minus the
 * lock: each parse has its own stream, so there is nothing to guard.</p>
 *
 * <p>Everything else is BouncyCastle's own code path, so what parses, what
 * is rejected and with which exception do not change:
 * {@link ASN1InputStream#ASN1InputStream(java.io.InputStream, int)} with the
 * input's length as its limit is exactly what
 * {@link ASN1InputStream#ASN1InputStream(byte[])} does, and the trailing-data
 * and {@link ClassCastException} handling below is copied from
 * {@code fromByteArray}.</p>
 */
final class ReceiptDer {

    private ReceiptDer() {}

    /** Same contract as {@link ASN1Primitive#fromByteArray}. */
    static ASN1Primitive fromByteArray(byte[] data) throws IOException {
        ASN1InputStream in = new ASN1InputStream(new UnsynchronizedInput(data), data.length);
        try {
            ASN1Primitive parsed = in.readObject();
            if (in.available() != 0) {
                throw new IOException("Extra data detected in stream");
            }
            return parsed;
        } catch (ClassCastException e) {
            throw Exceptions.ioException("cannot recognise object in stream", e);
        }
    }

    /**
     * {@link ByteArrayInputStream} with the three methods BouncyCastle calls
     * per byte re-implemented without {@code synchronized}, line for line from
     * the JDK's own. Still a {@code ByteArrayInputStream}, so any
     * {@code instanceof} check in BouncyCastle sees what it saw before.
     */
    static final class UnsynchronizedInput extends ByteArrayInputStream {

        UnsynchronizedInput(byte[] buf) {
            super(buf);
        }

        @Override
        public int read() {
            return (pos < count) ? (buf[pos++] & 0xff) : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (b == null) {
                throw new NullPointerException();
            } else if (off < 0 || len < 0 || len > b.length - off) {
                throw new IndexOutOfBoundsException();
            }
            if (pos >= count) {
                return -1;
            }
            int avail = count - pos;
            if (len > avail) {
                len = avail;
            }
            if (len <= 0) {
                return 0;
            }
            System.arraycopy(buf, pos, b, off, len);
            pos += len;
            return len;
        }

        @Override
        public int available() {
            return count - pos;
        }
    }
}
