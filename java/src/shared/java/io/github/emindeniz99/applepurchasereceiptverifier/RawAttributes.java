package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** The defensive copy of the receipt models' {@code unknownAttributes} maps. */
final class RawAttributes {

    private RawAttributes() {}

    /** An unmodifiable copy in ascending type order, down to fresh arrays, since a shared {@code byte[]} can be rewritten in place. */
    static Map<Integer, List<byte[]>> copy(Map<Integer, List<byte[]>> attributes) {
        Map<Integer, List<byte[]>> copy = new TreeMap<>();
        for (Map.Entry<Integer, List<byte[]>> entry : attributes.entrySet()) {
            List<byte[]> values = new ArrayList<>(entry.getValue().size());
            for (byte[] value : entry.getValue()) {
                values.add(Objects.requireNonNull(value, "attribute value").clone());
            }
            copy.put(Objects.requireNonNull(entry.getKey(), "attribute type"), Collections.unmodifiableList(values));
        }
        return Collections.unmodifiableMap(copy);
    }
}
