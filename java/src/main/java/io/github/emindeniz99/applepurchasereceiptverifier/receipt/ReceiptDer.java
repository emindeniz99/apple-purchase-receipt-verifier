package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;
import org.jspecify.annotations.Nullable;

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
     * The string BouncyCastle decodes from {@code der} when {@code der} is a
     * single primitive UTF8String or IA5String whose short-form length spans
     * the rest of the array, which is how receipts encode nearly every string
     * and date; {@code null} for any other shape, which the caller then
     * parses in full.
     *
     * <p>Same answer, including the same exception for invalid UTF-8: for
     * these two tags BouncyCastle's parse only copies the content octets, and
     * {@code getString()} hands them to exactly the {@link Strings} function
     * called here. A length octet of 0x80 or above (long form or indefinite)
     * or one that disagrees with the array's length is left to the parser,
     * which owns those errors.</p>
     */
    static @Nullable String shortString(byte[] der) {
        if (der.length < 2 || der[1] < 0 || der[1] != der.length - 2) {
            return null;
        }
        if (der[0] == BERTags.UTF8_STRING) {
            return Strings.fromUTF8ByteArray(Arrays.copyOfRange(der, 2, der.length));
        }
        if (der[0] == BERTags.IA5_STRING) {
            return Strings.fromByteArray(Arrays.copyOfRange(der, 2, der.length));
        }
        return null;
    }

    /**
     * The value of {@code der} when it is a single primitive INTEGER of one
     * to eight content octets, minimally encoded and non-negative, which is
     * every integer a genuine receipt carries; -1 for any other shape, which
     * the caller then parses in full.
     *
     * <p>Non-minimal encodings are left to the parser on purpose: whether
     * BouncyCastle accepts them depends on the
     * {@code org.bouncycastle.asn1.allow_unsafe_integer} system property.
     * Negative values are left to it too, so they fail with the message they
     * always had.</p>
     */
    static long shortNonNegativeInteger(byte[] der) {
        if (der.length < 3 || der.length > 10 || der[0] != BERTags.INTEGER || der[1] != der.length - 2) {
            return -1;
        }
        if (der[2] < 0 || (der.length > 3 && der[2] == 0 && der[3] >= 0)) {
            return -1;
        }
        long value = 0;
        for (int i = 2; i < der.length; i++) {
            value = (value << 8) | (der[i] & 0xff);
        }
        return value;
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
