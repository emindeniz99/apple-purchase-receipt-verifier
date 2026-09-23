package io.github.emindeniz99.applepurchasereceiptverifier.receipt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
     * The attributes of {@code der} when it is exactly the DER every genuine
     * receipt uses for a payload or an in-app purchase:
     * {@code SET OF SEQUENCE { INTEGER type, INTEGER version, OCTET STRING
     * value }}, all primitive and definite-length with minimal lengths, the
     * type non-negative and at most four octets, both integers minimally
     * encoded, and nothing after the SET. {@code null} for every other input,
     * which the caller then parses in full.
     *
     * <p>Each input accepted here is one BouncyCastle parses to a SET of
     * three-element SEQUENCEs whose attributes
     * {@code ReceiptVerifier.Attribute.of} reads without error, to the same
     * types and values: minimal definite lengths and minimal integers are
     * the encodings BouncyCastle accepts unconditionally, and a four-octet
     * non-negative integer always fits the attribute type's range. Anything
     * outside that (long-form lengths over three octets, indefinite lengths,
     * constructed strings, a version that is not an INTEGER, a fourth field,
     * a negative or oversized type, trailing bytes, the Xcode double wrap)
     * goes to the parser, which owns every error message. What made the
     * parser slow here is what this skips: an input stream, a vector and a
     * handful of objects for each of the thousands of elements.</p>
     */
    static @Nullable List<ReceiptVerifier.Attribute> simpleAttributes(byte[] der) {
        Cursor cursor = new Cursor(der);
        int setLength = cursor.header(BERTags.SET | BERTags.CONSTRUCTED, der.length);
        if (setLength < 0 || cursor.pos + setLength != der.length) {
            return null;
        }
        List<ReceiptVerifier.Attribute> attributes = new ArrayList<ReceiptVerifier.Attribute>();
        while (cursor.pos < der.length) {
            int sequenceLength = cursor.header(BERTags.SEQUENCE | BERTags.CONSTRUCTED, der.length);
            if (sequenceLength < 0) {
                return null;
            }
            int sequenceEnd = cursor.pos + sequenceLength;

            int typeLength = cursor.header(BERTags.INTEGER, sequenceEnd);
            if (typeLength < 1 || typeLength > 4 || nonMinimalOrNegative(der, cursor.pos, typeLength)) {
                return null;
            }
            int type = 0;
            for (int i = cursor.pos; i < cursor.pos + typeLength; i++) {
                type = (type << 8) | (der[i] & 0xff);
            }
            cursor.pos += typeLength;

            int versionLength = cursor.header(BERTags.INTEGER, sequenceEnd);
            // BouncyCastle's own malformed-integer rule; the version's value
            // is never read, so its sign does not matter.
            if (versionLength < 1 || (versionLength > 1 && der[cursor.pos] == (der[cursor.pos + 1] >> 7))) {
                return null;
            }
            cursor.pos += versionLength;

            int valueLength = cursor.header(BERTags.OCTET_STRING, sequenceEnd);
            if (valueLength < 0) {
                return null;
            }
            byte[] value = Arrays.copyOfRange(der, cursor.pos, cursor.pos + valueLength);
            cursor.pos += valueLength;
            if (cursor.pos != sequenceEnd) {
                return null;
            }
            attributes.add(new ReceiptVerifier.Attribute(type, value));
        }
        return attributes;
    }

    private static boolean nonMinimalOrNegative(byte[] der, int start, int length) {
        return der[start] < 0 || (length > 1 && der[start] == 0 && der[start + 1] >= 0);
    }

    /** A read position in a DER array. */
    private static final class Cursor {
        private final byte[] der;
        int pos;

        Cursor(byte[] der) {
            this.der = der;
        }

        /**
         * Reads the identifier and length octets of an element with exactly
         * {@code tag}, whose content must end at or before {@code limit}, and
         * moves to its content. Returns the content length, or -1 (without
         * moving) for any other tag, a length that is not minimal DER of at
         * most three octets, or content that would run past {@code limit}.
         */
        int header(int tag, int limit) {
            int p = pos;
            if (p + 2 > limit || der[p] != (byte) tag) {
                return -1;
            }
            p++;
            int first = der[p++] & 0xff;
            int length;
            if (first < 0x80) {
                length = first;
            } else {
                int count = first & 0x7F;
                if (count < 1 || count > 3 || p + count > limit || der[p] == 0) {
                    return -1;
                }
                length = 0;
                for (int i = 0; i < count; i++) {
                    length = (length << 8) | (der[p++] & 0xff);
                }
                if (length < 0x80) {
                    return -1;
                }
            }
            if (length > limit - p) {
                return -1;
            }
            pos = p;
            return length;
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
