package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * The ASN.1 nesting bounds, checked on the encoding before BouncyCastle
 * parses it: BouncyCastle's own bound is looser, counts one level fewer and
 * can be raised by a system property, and it joins the chunks of a
 * constructed string at any depth. An encoding the walk cannot follow is
 * left to the parser that runs next.
 */
final class Asn1Depth {

    /** At most this many constructed values inside one another. */
    static final int MAX_DEPTH = 32;

    /**
     * At most this many constructed levels in one constructed string, the
     * string itself counted as 1: OpenSSL's bound ({@code
     * ASN1_MAX_STRING_NEST}, which counts from 0), so the implementations
     * refuse the same strings. A string is a universal constructed value
     * other than a SEQUENCE or a SET; inside one, every constructed chunk is
     * one more level, whatever its tag, as OpenSSL counts them.
     */
    static final int MAX_STRING_NEST = 6;

    private Asn1Depth() {}

    /** Whether {@code der} nests more than {@link #MAX_DEPTH} constructed values. */
    static boolean exceeded(byte[] der) {
        try {
            walk(der, 0, der.length, 0, 0, false);
            return false;
        } catch (TooDeep e) {
            return true;
        }
    }

    /**
     * Whether a constructed string anywhere in {@code der}, at any depth,
     * nests more than {@link #MAX_STRING_NEST} constructed levels. Meant for
     * an encoding {@link #exceeded} accepted.
     */
    static boolean stringNestExceeded(byte[] der) {
        try {
            walk(der, 0, der.length, 0, 0, true);
            return false;
        } catch (TooDeep e) {
            return e.string;
        }
    }

    /**
     * Walks the value at {@code at}, below {@code depth} constructed values
     * and, with {@code strings}, a chunk of a string of {@code string}
     * constructed levels (0 outside any); returns where it ends, or -1 when
     * the encoding cannot be followed.
     */
    private static int walk(byte[] der, int at, int end, int depth, int string, boolean strings) throws TooDeep {
        if (at >= end) {
            return -1;
        }
        int tag = der[at] & 0xFF;
        int position = at + 1;
        if ((tag & 0x1F) == 0x1F) {
            // A multi-byte tag number: continuation octets have the top bit set.
            while (position < end && (der[position] & 0x80) != 0) {
                position++;
            }
            position++;
        }
        boolean constructed = (tag & 0x20) != 0;
        if (constructed && depth >= MAX_DEPTH) {
            throw new TooDeep(false);
        }
        int level = 0;
        if (constructed && strings) {
            boolean universalString = (tag & 0xC0) == 0 && (tag & 0x1F) != 0x10 && (tag & 0x1F) != 0x11;
            level = string > 0 ? string + 1 : universalString ? 1 : 0;
            if (level > MAX_STRING_NEST) {
                throw new TooDeep(true);
            }
        }
        if (position >= end) {
            return -1;
        }
        int first = der[position++] & 0xFF;
        if (first == 0x80) {
            if (!constructed) {
                return -1;
            }
            // Indefinite length: children until the end-of-contents octets.
            while (position >= 0) {
                if (position + 1 < end && der[position] == 0 && der[position + 1] == 0) {
                    return position + 2;
                }
                position = walk(der, position, end, depth + 1, level, strings);
            }
            return -1;
        }
        long length;
        if (first < 0x80) {
            length = first;
        } else {
            int count = first & 0x7F;
            if (count > 4 || position + count > end) {
                return -1;
            }
            length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | (der[position++] & 0xFF);
            }
        }
        if (length > end - position) {
            return -1;
        }
        int contentEnd = position + (int) length;
        if (constructed) {
            while (position >= 0 && position < contentEnd) {
                position = walk(der, position, contentEnd, depth + 1, level, strings);
            }
            if (position < 0) {
                return -1;
            }
        }
        return contentEnd;
    }

    private static final class TooDeep extends Exception {
        private static final long serialVersionUID = 1L;

        /** A string's chunks, not the constructed values, went too deep. */
        final boolean string;

        TooDeep(boolean string) {
            super(null, null, false, false);
            this.string = string;
        }
    }
}
