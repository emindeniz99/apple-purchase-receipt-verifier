package io.github.emindeniz99.applepurchasereceiptverifier;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** The defensive copy of the receipt models' {@code unknownAttributes} maps. */
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
        Map<Integer, List<byte[]>> copy = new LinkedHashMap<>(attributes.size());
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
