package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.jspecify.annotations.Nullable;

/**
 * A verifier's revocation state (docs/design/revocation.md): built once by
 * {@link #build}, then read by every call through {@link #check}. Immutable,
 * so one instance serves every thread.
 *
 * <p>Three layers, all offline: the built-in list, always on; the caller's
 * {@code distrust} entries; and the lists the caller passed, at most one
 * held per issuer. A certificate's revocation key is the issuer id of the
 * certificate above it on the verified path and its own serial (§2).</p>
 */
final class Revocation {

    /** More lists than this are refused. */
    static final int MAX_LISTS = 16;

    /** More entries than this, over all lists, are refused. */
    static final int MAX_ENTRIES = 100_000;

    /** More distrust entries than this are refused. */
    static final int MAX_DISTRUST = 1_000;

    /** The list held for one issuer. */
    private static final class Held {
        final long nextUpdate;
        /** The list's entries but its removeFromCRL ones, which revoke nothing. */
        final Map<String, Integer> entries;

        Held(RevocationList list) {
            // Only a list with a nextUpdate is held (§4).
            this.nextUpdate = list.nextUpdate == null ? Long.MIN_VALUE : list.nextUpdate;
            Map<String, Integer> listed = new HashMap<>();
            for (Map.Entry<String, Integer> entry : list.entries.entrySet()) {
                if (entry.getValue() != RevocationList.REMOVE_FROM_CRL) {
                    listed.put(entry.getKey(), entry.getValue());
                }
            }
            this.entries = listed;
        }
    }

    /** A certificate that may sign lists: a configured root or an accepted issuer. */
    private static final class Signer {
        final X509Certificate certificate;
        final Der.CertificateNames names;
        final String id;
        final byte @Nullable [] subjectKeyIdentifier;
        final @Nullable PublicKey key;

        Signer(X509Certificate certificate) {
            this.certificate = certificate;
            this.names = Der.names(certificate);
            this.id = names.issuerId();
            this.subjectKeyIdentifier = subjectKeyIdentifier(certificate);
            PublicKey decoded;
            try {
                decoded = certificate.getPublicKey();
            } catch (RuntimeException e) {
                decoded = null;
            }
            this.key = decoded;
        }

        /** §4: a candidate for {@code list} by name, and by key identifier when the list names one. */
        boolean candidateFor(RevocationList list) {
            if (!Arrays.equals(names.subject, list.issuer)) {
                return false;
            }
            return !list.hasAuthorityKeyIdentifier
                    || subjectKeyIdentifier != null && Arrays.equals(subjectKeyIdentifier, list.authorityKeyIdentifier);
        }
    }

    /** An issuer certificate accepted structurally (§6), with the root that signed it. */
    private static final class Candidate {
        final Signer signer;
        final Signer root;

        Candidate(Signer signer, Signer root) {
            this.signer = signer;
            this.root = root;
        }
    }

    private final Set<String> builtIn;
    private final Set<String> distrust;
    private final Map<String, Held> held;
    private final Map<X509Certificate, String> anchorIds;
    private final List<String> urls;
    private final @Nullable Instant validUntil;

    private Revocation(
            Set<String> builtIn,
            Set<String> distrust,
            Map<String, Held> held,
            Map<X509Certificate, String> anchorIds,
            List<String> urls,
            @Nullable Instant validUntil) {
        this.builtIn = builtIn;
        this.distrust = distrust;
        this.held = held;
        this.anchorIds = anchorIds;
        this.urls = urls;
        this.validUntil = validUntil;
    }

    /** {@link Verifier#revocationUrls()}. */
    List<String> urls() {
        return urls;
    }

    /** {@link Verifier#revocationValidUntil()}. */
    @Nullable
    Instant validUntil() {
        return validUntil;
    }

    /**
     * Builds the state for {@code roots} (in configuration order) from
     * {@code config}'s revocation settings and {@code builtInList}.
     *
     * @throws IllegalArgumentException naming the first problem and its index
     */
    static Revocation build(Collection<X509Certificate> roots, Config config, BuiltInRevocations builtInList) {
        Set<String> distrust = distrust(config.distrust());

        List<Signer> rootSigners = new ArrayList<>();
        Map<X509Certificate, String> anchorIds = new HashMap<>();
        for (X509Certificate root : roots) {
            Signer signer = new Signer(root);
            rootSigners.add(signer);
            anchorIds.put(root, signer.id);
        }

        List<RevocationList> lists = lists(config.revocationLists());

        // §6, all but revocation: the built-in issuers (dropped silently when
        // they fail) and the added ones (refused). A revoked issuer of either
        // kind is set aside below.
        List<Candidate> builtInIssuers = new ArrayList<>();
        for (BuiltInRevocations.Issuer issuer : builtInList.issuers) {
            if (issuer.certificate != null) {
                Signer signer = new Signer(issuer.certificate);
                Signer root = signingRoot(signer, rootSigners);
                if (root != null && issuerProblem(signer.certificate) == null) {
                    builtInIssuers.add(new Candidate(signer, root));
                }
            }
        }
        List<Candidate> addedIssuers = new ArrayList<>();
        List<X509Certificate> added = config.revocationIssuers();
        for (int i = 0; i < added.size(); i++) {
            Signer signer = new Signer(bouncyCastle(added.get(i), i));
            Signer root = signingRoot(signer, rootSigners);
            if (root == null) {
                throw refused("revocationIssuers[" + i + "] is not signed by a configured root");
            }
            String problem = issuerProblem(signer.certificate);
            if (problem != null) {
                throw refused("revocationIssuers[" + i + "] " + problem);
            }
            addedIssuers.add(new Candidate(signer, root));
        }

        // The roots' own lists first: an issuer's revocation reads them.
        Map<Integer, Signer> signedBy = new HashMap<>();
        for (int i = 0; i < lists.size(); i++) {
            Signer root = verifiedBy(lists.get(i), rootSigners);
            if (root != null) {
                checkAge(lists.get(i), root.id, builtInList, i);
                signedBy.put(i, root);
            }
        }
        Map<String, Held> rootLists = keep(lists, signedBy);

        Set<String> builtInKeys = builtInList.revoked;
        List<Candidate> accepted = new ArrayList<>();
        Set<String> acceptedBuiltIn = new HashSet<>();
        List<Candidate> acceptedAdded = new ArrayList<>();
        // §6: an issuer, built-in or added, dropped because it is revoked; its own list is set aside below.
        List<Signer> revokedIssuers = new ArrayList<>();
        for (Candidate issuer : builtInIssuers) {
            if (issuerRevoked(issuer, builtInKeys, distrust, rootLists)) {
                revokedIssuers.add(issuer.signer);
            } else {
                accepted.add(issuer);
                acceptedBuiltIn.add(issuer.signer.id);
            }
        }
        for (Candidate issuer : addedIssuers) {
            if (issuerRevoked(issuer, builtInKeys, distrust, rootLists)) {
                revokedIssuers.add(issuer.signer);
            } else {
                accepted.add(issuer);
                acceptedAdded.add(issuer);
            }
        }

        List<Signer> issuerSigners = new ArrayList<>();
        for (Candidate issuer : accepted) {
            issuerSigners.add(issuer.signer);
        }
        for (int i = 0; i < lists.size(); i++) {
            if (signedBy.containsKey(i)) {
                continue;
            }
            Signer issuer = verifiedBy(lists.get(i), issuerSigners);
            if (issuer == null && verifiedBy(lists.get(i), revokedIssuers) != null) {
                // The list of a revoked issuer is neither held nor refused: every path through
                // that issuer already fails on the issuer itself, and refusing would leave a host that
                // refreshes from the URLs it was given on its old verifier.
                continue;
            }
            if (issuer == null) {
                boolean named = false;
                for (Signer signer : rootSigners) {
                    named |= signer.candidateFor(lists.get(i));
                }
                for (Signer signer : issuerSigners) {
                    named |= signer.candidateFor(lists.get(i));
                }
                throw refused("revocationLists[" + i + "] "
                        + (named
                                ? "does not verify with the key of any configured root or accepted issuer it names"
                                : "names no configured root or accepted issuer, by name and key identifier"));
            }
            checkAge(lists.get(i), issuer.id, builtInList, i);
            signedBy.put(i, issuer);
        }
        Map<String, Held> held = keep(lists, signedBy);

        // §7: the built-in issuers that chain to the configured roots, then
        // the added ones. A revoked added issuer is not expected, but its
        // distribution points, where its own revocation is published, stay.
        Set<String> expected = new LinkedHashSet<>();
        Set<String> urls = new LinkedHashSet<>();
        Set<String> rootIds = new HashSet<>(anchorIds.values());
        for (BuiltInRevocations.Issuer issuer : builtInList.issuers) {
            if (issuer.certificate == null ? rootIds.contains(issuer.id) : acceptedBuiltIn.contains(issuer.id)) {
                expected.add(issuer.id);
                urls.add(issuer.list);
            }
        }
        for (Candidate issuer : acceptedAdded) {
            expected.add(issuer.signer.id);
        }
        for (Candidate issuer : addedIssuers) {
            urls.addAll(distributionPoints(issuer.signer.certificate));
        }
        return new Revocation(
                builtInKeys,
                Collections.unmodifiableSet(distrust),
                Collections.unmodifiableMap(held),
                Collections.unmodifiableMap(anchorIds),
                Collections.unmodifiableList(new ArrayList<>(urls)),
                validUntil(expected, held));
    }

    /**
     * §7: the earliest nextUpdate among the expected issuers' held lists;
     * null when one of them has none, or when no issuer is expected.
     */
    private static @Nullable Instant validUntil(Set<String> expected, Map<String, Held> held) {
        long earliest = Long.MAX_VALUE;
        for (String id : expected) {
            Held list = held.get(id);
            if (list == null) {
                return null;
            }
            earliest = Math.min(earliest, list.nextUpdate);
        }
        return expected.isEmpty() ? null : Instant.ofEpochMilli(earliest);
    }

    /**
     * §3 for a verified path: {@code path} leaf first, the anchor excluded,
     * then {@code anchor}, which is never checked itself. {@code now} is the
     * call's clock, which decides only whether a {@code certificateHold}
     * entry's list is fresh.
     */
    void check(List<X509Certificate> path, X509Certificate anchor, long now, String what) throws VerificationException {
        for (int i = 0; i < path.size(); i++) {
            X509Certificate certificate = path.get(i);
            String serial = Der.serialHex(certificate.getSerialNumber());
            if (serial == null) {
                continue;
            }
            String issuerId;
            if (i + 1 < path.size()) {
                issuerId = Der.names(path.get(i + 1)).issuerId();
            } else {
                String known = anchorIds.get(anchor);
                issuerId = known != null ? known : Der.names(anchor).issuerId();
            }
            String key = BuiltInRevocations.key(issuerId, serial);
            String layer = null;
            if (builtIn.contains(key)) {
                layer = "built-in list";
            } else if (distrust.contains(key)) {
                layer = "distrust";
            } else {
                Held list = held.get(issuerId);
                Integer reason = list == null ? null : list.entries.get(serial);
                if (reason != null && (reason != RevocationList.CERTIFICATE_HOLD || now <= list.nextUpdate)) {
                    layer = "Apple's list";
                }
            }
            if (layer != null) {
                throw new VerificationException(
                        Reason.CERTIFICATE_REVOKED,
                        what + " certificate with serial " + serial + " is revoked: " + layer);
            }
        }
    }

    // ------------------------------------------------------------ building

    private static IllegalArgumentException refused(String problem) {
        return new IllegalArgumentException("revocation settings refused: " + problem);
    }

    /** The distrust entries as revocation keys (§2, §4). */
    private static Set<String> distrust(List<RevokedCertificate> entries) {
        if (entries.size() > MAX_DISTRUST) {
            throw refused("distrust holds " + entries.size() + " entries, more than " + MAX_DISTRUST);
        }
        Set<String> keys = new HashSet<>();
        for (int i = 0; i < entries.size(); i++) {
            RevokedCertificate entry = entries.get(i);
            String issuer = entry.issuer();
            if (issuer.length() != 64 || !Der.isHex(issuer)) {
                throw refused("distrust[" + i + "] issuer is not 64 hex digits");
            }
            String serial = Der.normaliseHex(entry.serial());
            if (serial == null) {
                throw refused("distrust[" + i + "] serial is not hex");
            }
            keys.add(BuiltInRevocations.key(issuer.toLowerCase(Locale.ROOT), serial));
        }
        return keys;
    }

    /** The bounds, then each list's parse, in input order. */
    private static List<RevocationList> lists(List<byte[]> files) {
        if (files.size() > MAX_LISTS) {
            throw refused("revocationLists holds " + files.size() + " lists, more than " + MAX_LISTS);
        }
        List<RevocationList> lists = new ArrayList<>();
        long entries = 0;
        for (int i = 0; i < files.size(); i++) {
            byte[] file = files.get(i);
            if (file.length > RevocationList.MAX_LIST_BYTES) {
                throw refused("revocationLists[" + i + "] is over 1 MiB");
            }
            RevocationList list;
            try {
                list = RevocationList.parse(file);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "revocation settings refused: revocationLists[" + i + "] is not a DER CRL", e);
            }
            if (list.hasAuthorityKeyIdentifier && list.authorityKeyIdentifier == null) {
                throw refused("revocationLists[" + i + "] has an AuthorityKeyIdentifier without a keyIdentifier");
            }
            entries += list.entryCount;
            if (entries > MAX_ENTRIES) {
                throw refused("revocationLists[" + i + "] brings the entries in all to more than " + MAX_ENTRIES);
            }
            lists.add(list);
        }
        return lists;
    }

    /** The first of {@code signers}, in order, that is a candidate for {@code list} and whose key verifies it. */
    private static @Nullable Signer verifiedBy(RevocationList list, List<Signer> signers) {
        for (Signer signer : signers) {
            if (signer.key != null && signer.candidateFor(list) && list.signedBy(signer.key)) {
                return signer;
            }
        }
        return null;
    }

    /** §4: refuses a list older than the newest the built-in file records for its issuer. */
    private static void checkAge(RevocationList list, String issuerId, BuiltInRevocations builtInList, int index) {
        BuiltInRevocations.Issuer known = builtInList.issuer(issuerId);
        if (known == null) {
            return;
        }
        boolean older = list.crlNumber != null && known.newestNumber != null
                ? list.crlNumber.compareTo(known.newestNumber) < 0
                : list.thisUpdate < known.newestThisUpdate;
        if (older) {
            throw refused("revocationLists[" + index + "] is older than the newest list the built-in list records"
                    + " for its issuer");
        }
    }

    /**
     * §4: for each issuer, the one list kept among those it signed that the
     * profile supports: the highest CRL Number; when any lacks one, the
     * latest thisUpdate; on a tie, the DER that sorts first.
     */
    private static Map<String, Held> keep(List<RevocationList> lists, Map<Integer, Signer> signedBy) {
        Map<String, List<RevocationList>> byIssuer = new HashMap<>();
        for (Map.Entry<Integer, Signer> signed : signedBy.entrySet()) {
            RevocationList list = lists.get(signed.getKey());
            if (list.unsupported == null) {
                byIssuer.computeIfAbsent(signed.getValue().id, id -> new ArrayList<>())
                        .add(list);
            }
        }
        Map<String, Held> held = new HashMap<>();
        for (Map.Entry<String, List<RevocationList>> issuer : byIssuer.entrySet()) {
            List<RevocationList> candidates = issuer.getValue();
            boolean numbered = true;
            for (RevocationList list : candidates) {
                numbered &= list.crlNumber != null;
            }
            RevocationList kept = null;
            for (RevocationList list : candidates) {
                if (kept == null || newer(list, kept, numbered)) {
                    kept = list;
                }
            }
            held.put(issuer.getKey(), new Held(kept));
        }
        return held;
    }

    private static boolean newer(RevocationList a, RevocationList b, boolean numbered) {
        int order = numbered ? a.crlNumber.compareTo(b.crlNumber) : Long.compare(a.thisUpdate, b.thisUpdate);
        if (order != 0) {
            return order > 0;
        }
        return compareUnsigned(a.der, b.der) < 0;
    }

    /** Byte by byte, unsigned; a prefix sorts first. */
    private static int compareUnsigned(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            int order = Integer.compare(a[i] & 0xff, b[i] & 0xff);
            if (order != 0) {
                return order;
            }
        }
        return Integer.compare(a.length, b.length);
    }

    /**
     * §6: the first configured root whose subject is the certificate's
     * issuer Name, byte for byte, and whose key verifies its signature.
     */
    private static @Nullable Signer signingRoot(Signer issuer, List<Signer> roots) {
        for (Signer root : roots) {
            if (root.key != null
                    && Arrays.equals(issuer.names.issuer, root.names.subject)
                    && AppleTrust.signedBy(issuer.certificate, root.key)) {
                return root;
            }
        }
        return null;
    }

    /** §6, the rest but revocation: what keeps {@code certificate} from signing lists, or null. */
    private static @Nullable String issuerProblem(X509Certificate certificate) {
        int pathLength;
        try {
            pathLength = certificate.getBasicConstraints();
        } catch (RuntimeException e) {
            // A pathLenConstraint beyond an int makes BouncyCastle throw an
            // ArithmeticException. It must not leave build() as one: the
            // documented refusal is an IllegalArgumentException with an index.
            return "has a basicConstraints that does not read";
        }
        if (pathLength == -1) {
            return "is not a CA";
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage != null && (keyUsage.length < 7 || !keyUsage[6])) {
            return "has a keyUsage without cRLSign";
        }
        if (certificate.getExtensionValue(AppleTrust.INTERMEDIATE_OID) == null) {
            return "lacks Apple's WWDR marker OID " + AppleTrust.INTERMEDIATE_OID;
        }
        return null;
    }

    /**
     * §6: an issuer whose own revocation key, under the root that signed it,
     * is on the built-in list, in distrust, or on that root's held list. No
     * clock reads here, so a certificateHold entry counts.
     */
    private static boolean issuerRevoked(
            Candidate issuer, Set<String> builtIn, Set<String> distrust, Map<String, Held> rootLists) {
        String serial = Der.serialHex(issuer.signer.certificate.getSerialNumber());
        if (serial == null) {
            return false;
        }
        String key = BuiltInRevocations.key(issuer.root.id, serial);
        if (builtIn.contains(key) || distrust.contains(key)) {
            return true;
        }
        Held list = rootLists.get(issuer.root.id);
        return list != null && list.entries.containsKey(serial);
    }

    /** The certificate as BouncyCastle reads it, which {@link AppleTrust#signedBy} needs. */
    private static X509Certificate bouncyCastle(X509Certificate certificate, int index) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509", BouncyCastle.PROVIDER)
                    .generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
        } catch (CertificateException | RuntimeException e) {
            throw new IllegalArgumentException(
                    "revocation settings refused: revocationIssuers[" + index + "] does not parse", e);
        }
    }

    private static byte @Nullable [] subjectKeyIdentifier(X509Certificate certificate) {
        byte[] value = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        if (value == null) {
            return null;
        }
        try {
            return ASN1OctetString.getInstance(
                            ASN1OctetString.getInstance(value).getOctets())
                    .getOctets();
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** §7: the http and https URIs of a certificate's cRLDistributionPoints, in order. */
    private static List<String> distributionPoints(X509Certificate certificate) {
        List<String> urls = new ArrayList<>();
        byte[] value = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (value == null) {
            return urls;
        }
        try {
            CRLDistPoint points =
                    CRLDistPoint.getInstance(ASN1OctetString.getInstance(value).getOctets());
            for (DistributionPoint point : points.getDistributionPoints()) {
                DistributionPointName name = point.getDistributionPoint();
                if (name == null || name.getType() != DistributionPointName.FULL_NAME) {
                    continue;
                }
                for (GeneralName general :
                        GeneralNames.getInstance(name.getName()).getNames()) {
                    if (general.getTagNo() != GeneralName.uniformResourceIdentifier) {
                        continue;
                    }
                    String uri = general.getName().toString();
                    int colon = uri.indexOf(':');
                    String scheme = colon < 0 ? "" : uri.substring(0, colon).toLowerCase(Locale.ROOT);
                    // http://... and https://..., the scheme in either case.
                    if ((scheme.equals("http") || scheme.equals("https")) && uri.startsWith("//", colon + 1)) {
                        urls.add(uri);
                    }
                }
            }
        } catch (RuntimeException e) {
            // An extension that does not decode names no URL.
        }
        return urls;
    }
}
