# Java: the cost of one OID comparison: source

The note is [`../2026-10-13-java-oid-tables.md`](../2026-10-13-java-oid-tables.md). `OidEqualsCost.java` builds two OIDs of 8, 300, 3,000 and 4,000 content octets that differ only in the last octet, then times 10^6 `equals` calls and 2,000 `hashCode` calls after a warm-up. It builds no colliding table.

Run on JDK 21.0.10 with bcprov 1.86, `$SCRATCH` any directory outside the repository:
`javac --release 8 -d "$SCRATCH" -cp bcprov-jdk18on-1.86.jar OidEqualsCost.java`, then `java -cp "$SCRATCH:bcprov-jdk18on-1.86.jar" OidEqualsCost`.

Results, 10^6 comparisons, warm, three runs on 2026-10-14: 5 to 6 ms at 8 octets, 73 to 84 ms at 3,000, 101 to 109 ms at 4,000 (BouncyCastle's longest).
