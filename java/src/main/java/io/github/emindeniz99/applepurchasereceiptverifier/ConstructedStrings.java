package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Joins the constructed strings BouncyCastle cannot build. BER lets a string
 * of any type arrive in chunks (X.690 8.23.6), and OpenSSL joins them
 * wherever it decodes a value; BouncyCastle builds only a constructed BIT
 * STRING or OCTET STRING and refuses every other type. So before BouncyCastle
 * parses the receipt payload, each such string becomes the primitive of the
 * same type holding its joined octets, which BouncyCastle then judges as it
 * judges any primitive. Nothing else changes: the octets Java keeps come
 * from OCTET STRINGs, which are never rewritten. Chunks of any tag are
 * joined, as OpenSSL joins them.
 */
final class ConstructedStrings {

    private final byte[] der;

    /**
     * The content length, once joined, of each value the join rewrites, by
     * offset: the joined strings and every constructed value around one. A
     * value not here is copied as it is.
     */
    private final Map<Integer, Integer> rewritten = new HashMap<>();

    /** Where the value {@link #measure} or {@link #write} last read ends in {@link #der}. */
    private int end;

    private ConstructedStrings(byte[] der) {
        this.der = der;
    }

    /**
     * {@code der} with each such string joined, and what follows the value
     * kept for BouncyCastle to refuse; {@code der} itself when there is none
     * or the encoding cannot be followed, which BouncyCastle then judges.
     * Meant for an encoding {@link Asn1Depth} accepted.
     */
    static byte[] joined(byte[] der) {
        ConstructedStrings strings = new ConstructedStrings(der);
        try {
            int size = strings.measure(0, der.length, 0);
            if (strings.rewritten.isEmpty()) {
                return der;
            }
            int valueEnd = strings.end;
            ByteArrayOutputStream out = new ByteArrayOutputStream(size + der.length - valueEnd);
            strings.write(0, der.length, out);
            out.write(der, valueEnd, der.length - valueEnd);
            return out.toByteArray();
        } catch (CannotFollow e) {
            return der;
        }
    }

    /**
     * A constructed value to join: universal, and neither a type BouncyCastle
     * builds constructed (BIT STRING, OCTET STRING, EXTERNAL, SEQUENCE, SET)
     * nor one that is primitive only (BOOLEAN, INTEGER, NULL, OBJECT
     * IDENTIFIER, ENUMERATED), which OpenSSL refuses and BouncyCastle still
     * does.
     */
    private static boolean joinable(byte identifier) {
        if ((identifier & 0xE0) != 0x20) {
            return false;
        }
        switch (identifier & 0x1F) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 8:
            case 10:
            case 16:
            case 17:
            case 31:
                return false;
            default:
                return true;
        }
    }

    /** The encoded size of the value at {@code at} once joined. */
    private int measure(int at, int limit, int depth) throws CannotFollow {
        Header header = new Header(der, at, limit, depth);
        if (!header.constructed) {
            end = header.contentEnd;
            return end - at;
        }
        boolean join = joinable(der[at]);
        int inside = rewritten.size();
        int content = 0;
        int position = header.content;
        while (more(header, position, limit, join)) {
            content += join
                    ? joinedLength(position, header.childLimit(limit), depth + 1)
                    : measure(position, header.childLimit(limit), depth + 1);
            position = end;
        }
        end = header.indefinite ? position + 2 : position;
        int size;
        if (join) {
            size = 1 + lengthOctets(content) + content;
        } else if (header.indefinite) {
            size = header.content - at + content + 2;
        } else if (content == header.contentEnd - header.content) {
            size = end - at;
        } else {
            size = header.identifierEnd - at + lengthOctets(content) + content;
        }
        // A string joined inside keeps this value's size when it had no chunks.
        if (join || rewritten.size() > inside) {
            rewritten.put(at, content);
        }
        return size;
    }

    /** The joined octets of the chunk at {@code at}: its content, or its chunks' joined. */
    private int joinedLength(int at, int limit, int depth) throws CannotFollow {
        Header header = new Header(der, at, limit, depth);
        if (!header.constructed) {
            end = header.contentEnd;
            return end - header.content;
        }
        int length = 0;
        int position = header.content;
        while (more(header, position, limit, true)) {
            length += joinedLength(position, header.childLimit(limit), depth + 1);
            position = end;
        }
        end = header.indefinite ? position + 2 : position;
        return length;
    }

    /** Writes the value at {@code at}, joined, to {@code out}. */
    private void write(int at, int limit, ByteArrayOutputStream out) throws CannotFollow {
        Integer content = rewritten.get(at);
        if (content == null) {
            measure(at, limit, 0);
            out.write(der, at, end - at);
            return;
        }
        Header header = new Header(der, at, limit, 0);
        boolean join = joinable(der[at]);
        if (join) {
            out.write(der[at] & ~0x20);
            writeLength(out, content);
        } else if (header.indefinite || content == header.contentEnd - header.content) {
            // The same content length: the header as it was, as measure counts it.
            out.write(der, at, header.content - at);
        } else {
            out.write(der, at, header.identifierEnd - at);
            writeLength(out, content);
        }
        int position = header.content;
        while (more(header, position, limit, join)) {
            if (join) {
                writeJoined(position, header.childLimit(limit), out);
            } else {
                write(position, header.childLimit(limit), out);
            }
            position = end;
        }
        if (header.indefinite) {
            if (!join) {
                out.write(0);
                out.write(0);
            }
            position += 2;
        }
        end = position;
    }

    /** Writes the joined octets of the chunk at {@code at} to {@code out}. */
    private void writeJoined(int at, int limit, ByteArrayOutputStream out) throws CannotFollow {
        Header header = new Header(der, at, limit, 0);
        if (!header.constructed) {
            out.write(der, header.content, header.contentEnd - header.content);
            end = header.contentEnd;
            return;
        }
        int position = header.content;
        while (more(header, position, limit, true)) {
            writeJoined(position, header.childLimit(limit), out);
            position = end;
        }
        end = header.indefinite ? position + 2 : position;
    }

    /**
     * Whether a value starts at {@code position} inside the constructed value
     * {@code header} reads. Inside a string, an end-of-contents in a definite
     * length is refused, as OpenSSL refuses it, by leaving the string to
     * BouncyCastle.
     */
    private boolean more(Header header, int position, int limit, boolean string) throws CannotFollow {
        boolean endOfContents = position + 1 < limit && der[position] == 0 && der[position + 1] == 0;
        if (header.indefinite) {
            if (position >= limit) {
                throw new CannotFollow();
            }
            return !endOfContents;
        }
        if (position >= header.contentEnd) {
            return false;
        }
        if (string && endOfContents) {
            throw new CannotFollow();
        }
        return true;
    }

    private static int lengthOctets(int length) {
        int octets = 1;
        for (int rest = length; rest > 0x7F; rest >>>= 8) {
            octets++;
        }
        return octets;
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        int count = lengthOctets(length) - 1;
        if (count == 0) {
            out.write(length);
            return;
        }
        out.write(0x80 | count);
        for (int shift = 8 * (count - 1); shift >= 0; shift -= 8) {
            out.write(length >>> shift);
        }
    }

    /** One TLV header, read by the same rules as {@link Asn1Depth}'s walk. */
    private static final class Header {
        final boolean constructed;
        final boolean indefinite;
        /** Where the identifier octets end. */
        final int identifierEnd;
        /** Where the content starts. */
        final int content;
        /** Where a definite content ends. */
        final int contentEnd;

        Header(byte[] der, int at, int limit, int depth) throws CannotFollow {
            if (at >= limit) {
                throw new CannotFollow();
            }
            constructed = (der[at] & 0x20) != 0;
            if (constructed && depth >= Asn1Depth.MAX_DEPTH) {
                throw new CannotFollow();
            }
            int position = at + 1;
            if ((der[at] & 0x1F) == 0x1F) {
                while (position < limit && (der[position] & 0x80) != 0) {
                    position++;
                }
                position++;
            }
            if (position >= limit) {
                throw new CannotFollow();
            }
            identifierEnd = position;
            int first = der[position++] & 0xFF;
            indefinite = first == 0x80;
            if (indefinite) {
                if (!constructed) {
                    throw new CannotFollow();
                }
                content = position;
                contentEnd = -1;
                return;
            }
            long length = first;
            if (first > 0x80) {
                int count = first & 0x7F;
                if (count > 4 || position + count > limit) {
                    throw new CannotFollow();
                }
                length = 0;
                for (int i = 0; i < count; i++) {
                    length = (length << 8) | (der[position++] & 0xFF);
                }
            }
            if (length > limit - position) {
                throw new CannotFollow();
            }
            content = position;
            contentEnd = position + (int) length;
        }

        /** How far this value's children may reach. */
        int childLimit(int limit) {
            return indefinite ? limit : contentEnd;
        }
    }

    private static final class CannotFollow extends Exception {
        private static final long serialVersionUID = 1L;

        CannotFollow() {
            super(null, null, false, false);
        }
    }
}
