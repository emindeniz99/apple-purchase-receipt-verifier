package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.ArrayList;
import java.util.List;

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
     * At most this many constructed levels in one constructed OCTET STRING,
     * the string itself counted as 1. OpenSSL decodes six
     * ({@code ASN1_MAX_STRING_NEST}, which counts from 0) and refuses a
     * seventh, so the implementations refuse the same strings.
     */
    static final int MAX_STRING_NEST = 6;

    private static final int CONSTRUCTED_OCTET_STRING = 0x24;

    private static final int[] NONE = new int[0];

    private Asn1Depth() {}

    /** Whether {@code der} nests more than {@link #MAX_DEPTH} constructed values. */
    static boolean exceeded(byte[] der) {
        return exceeded(der, 0, MAX_DEPTH);
    }

    /**
     * Whether the value at {@code at} is a constructed OCTET STRING whose
     * chunks nest more than {@link #MAX_STRING_NEST} constructed levels.
     * Every constructed chunk is a level, whatever its tag, as OpenSSL counts
     * them; a chunk that is not an OCTET STRING is BouncyCastle's to refuse.
     */
    static boolean octetStringNestExceeded(byte[] der, int at) {
        return at >= 0
                && at < der.length
                && (der[at] & 0xFF) == CONSTRUCTED_OCTET_STRING
                && exceeded(der, at, MAX_STRING_NEST);
    }

    /**
     * Where the value {@code path} leads to starts: each index picks a value
     * inside the constructed value reached so far, from the value at 0. -1
     * when there is no such value or the walk cannot follow the encoding.
     */
    static int find(byte[] der, int... path) {
        int at = 0;
        for (int index : path) {
            int[] children = children(der, at, index + 1);
            if (children.length <= index) {
                return -1;
            }
            at = children[index];
        }
        return at;
    }

    /**
     * Where each of the first {@code limit} values inside the constructed
     * value at {@code at} starts, in order; none when {@code at} is not a
     * constructed value or the walk cannot follow it.
     */
    static int[] children(byte[] der, int at, int limit) {
        if (at < 0 || at >= der.length || (der[at] & 0x20) == 0) {
            return NONE;
        }
        int position = at + 1;
        if ((der[at] & 0x1F) == 0x1F) {
            while (position < der.length && (der[position] & 0x80) != 0) {
                position++;
            }
            position++;
        }
        if (position >= der.length) {
            return NONE;
        }
        int first = der[position++] & 0xFF;
        boolean indefinite = first == 0x80;
        int end = der.length;
        if (!indefinite) {
            long length = first;
            if (first > 0x80) {
                int count = first & 0x7F;
                if (count > 4 || position + count > end) {
                    return NONE;
                }
                length = 0;
                for (int i = 0; i < count; i++) {
                    length = (length << 8) | (der[position++] & 0xFF);
                }
            }
            if (length > end - position) {
                return NONE;
            }
            end = position + (int) length;
        }
        List<Integer> found = new ArrayList<>();
        try {
            while (found.size() < limit && position < end) {
                if (indefinite && position + 1 < end && der[position] == 0 && der[position + 1] == 0) {
                    break;
                }
                found.add(position);
                position = walk(der, position, end, 0, MAX_DEPTH);
                if (position < 0) {
                    return NONE;
                }
            }
        } catch (TooDeep e) {
            return NONE;
        }
        int[] starts = new int[found.size()];
        for (int i = 0; i < starts.length; i++) {
            starts[i] = found.get(i);
        }
        return starts;
    }

    /** Whether the value at {@code at} nests more than {@code max} constructed values. */
    private static boolean exceeded(byte[] der, int at, int max) {
        try {
            walk(der, at, der.length, 0, max);
            return false;
        } catch (TooDeep e) {
            return true;
        }
    }

    /**
     * Walks the value at {@code at}, below {@code depth} of at most
     * {@code max} constructed values; returns where it ends, or -1 when the
     * encoding cannot be followed.
     */
    private static int walk(byte[] der, int at, int end, int depth, int max) throws TooDeep {
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
        if (constructed && depth >= max) {
            throw new TooDeep();
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
                position = walk(der, position, end, depth + 1, max);
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
                position = walk(der, position, contentEnd, depth + 1, max);
            }
            if (position < 0) {
                return -1;
            }
        }
        return contentEnd;
    }

    private static final class TooDeep extends Exception {
        private static final long serialVersionUID = 1L;

        TooDeep() {
            super(null, null, false, false);
        }
    }
}
