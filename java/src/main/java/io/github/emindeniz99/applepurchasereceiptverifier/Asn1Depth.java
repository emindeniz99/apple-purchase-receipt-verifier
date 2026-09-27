package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * The ASN.1 nesting bound, checked on the encoding before BouncyCastle
 * builds anything from it.
 *
 * <p>BouncyCastle's own bound ({@code org.bouncycastle.asn1.max_cons_depth},
 * 64 by default) applies only where it reads indefinite lengths: a
 * definite-length DER encoding nested deeper parses without complaint, as
 * a test pins. So the bound is enforced here, on every encoding this
 * library parses before a signature has vouched for it, and counted the way
 * the Rust port counts it: at most {@link #MAX_DEPTH} constructed values
 * inside one another, the outermost included, and a primitive value inside
 * the innermost (owner, 2026-09-27, Q24).</p>
 *
 * <p>The walk judges depth and nothing else. An encoding it cannot follow
 * (a truncated length, say) is not its verdict to give: it answers "not too
 * deep" and leaves the refusal to the parser that runs next.</p>
 */
final class Asn1Depth {

    /** At most this many constructed values inside one another. */
    static final int MAX_DEPTH = 64;

    private Asn1Depth() {}

    /** Whether {@code der} nests more than {@link #MAX_DEPTH} constructed values. */
    static boolean exceeded(byte[] der) {
        try {
            walk(der, 0, der.length, 0);
            return false;
        } catch (TooDeep e) {
            return true;
        } catch (Unfollowable e) {
            return false;
        }
    }

    /** Walks the value at {@code at}, below {@code depth} constructed values; returns where it ends. */
    private static int walk(byte[] der, int at, int end, int depth) throws TooDeep, Unfollowable {
        if (at >= end) {
            throw new Unfollowable();
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
            throw new TooDeep();
        }
        if (position >= end) {
            throw new Unfollowable();
        }
        int first = der[position++] & 0xFF;
        if (first == 0x80) {
            if (!constructed) {
                throw new Unfollowable();
            }
            // Indefinite length: children until the end-of-contents octets.
            while (true) {
                if (position + 1 < end && der[position] == 0 && der[position + 1] == 0) {
                    return position + 2;
                }
                position = walk(der, position, end, depth + 1);
            }
        }
        long length;
        if (first < 0x80) {
            length = first;
        } else {
            int count = first & 0x7F;
            if (count > 4 || position + count > end) {
                throw new Unfollowable();
            }
            length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | (der[position++] & 0xFF);
            }
        }
        if (length > end - position) {
            throw new Unfollowable();
        }
        int contentEnd = position + (int) length;
        if (constructed) {
            while (position < contentEnd) {
                position = walk(der, position, contentEnd, depth + 1);
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

    private static final class Unfollowable extends Exception {
        private static final long serialVersionUID = 1L;

        Unfollowable() {
            super(null, null, false, false);
        }
    }
}
