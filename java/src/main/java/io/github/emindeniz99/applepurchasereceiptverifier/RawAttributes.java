package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Copy, equality and hash for the {@code unknownAttributes} maps of the receipt models. */
final class RawAttributes {

    private RawAttributes() {}

    /**
     * An unmodifiable copy of {@code attributes} in its own iteration order,
     * down to fresh arrays. The models copy on the way in and on the way out:
     * the unmodifiable wrapper only stops the map being re-keyed, and a shared
     * {@code byte[]} could otherwise be rewritten in place by one reader for
     * every other.
     */
    static Map<Integer, List<byte[]>> copy(Map<Integer, List<byte[]>> attributes) {
        Map<Integer, List<byte[]>> copy = new LinkedHashMap<Integer, List<byte[]>>(attributes.size());
        for (Map.Entry<Integer, List<byte[]>> entry : attributes.entrySet()) {
            List<byte[]> values = new ArrayList<byte[]>(entry.getValue().size());
            for (byte[] value : entry.getValue()) {
                values.add(Objects.requireNonNull(value, "attribute value").clone());
            }
            copy.put(Objects.requireNonNull(entry.getKey(), "attribute type"), Collections.unmodifiableList(values));
        }
        return Collections.unmodifiableMap(copy);
    }

    /** {@code attributes}, freshly built by the decoder and referenced by nothing else, made unmodifiable in place. */
    static Map<Integer, List<byte[]>> wrap(Map<Integer, List<byte[]>> attributes) {
        for (Map.Entry<Integer, List<byte[]>> entry : attributes.entrySet()) {
            entry.setValue(Collections.unmodifiableList(entry.getValue()));
        }
        return Collections.unmodifiableMap(attributes);
    }

    /**
     * Same types with the same octets, each type's values in the same order.
     * The order of the types is not compared, as {@code toJson()} writes them
     * sorted: two payloads are equal exactly when their JSON is.
     */
    static boolean equal(Map<Integer, List<byte[]>> a, Map<Integer, List<byte[]>> b) {
        if (a.size() != b.size()) {
            return false;
        }
        for (Map.Entry<Integer, List<byte[]>> entry : a.entrySet()) {
            List<byte[]> left = entry.getValue();
            List<byte[]> right = b.get(entry.getKey());
            if (right == null || left.size() != right.size()) {
                return false;
            }
            for (int i = 0; i < left.size(); i++) {
                if (!Arrays.equals(left.get(i), right.get(i))) {
                    return false;
                }
            }
        }
        return true;
    }

    static int hash(Map<Integer, List<byte[]>> attributes) {
        int hash = 0;
        for (Map.Entry<Integer, List<byte[]>> entry : attributes.entrySet()) {
            int valuesHash = 1;
            for (byte[] value : entry.getValue()) {
                valuesHash = 31 * valuesHash + Arrays.hashCode(value);
            }
            hash += entry.getKey().hashCode() ^ valuesHash;
        }
        return hash;
    }
}
