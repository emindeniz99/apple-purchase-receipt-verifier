package io.github.emindeniz99.applepurchasereceiptverifier;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * Writes the inputs of the certificate revocation cases of
 * {@code fixtures/cases.json} (docs/design/revocation.md §10) into the
 * directory given as the first argument (default
 * {@code fixtures/generated-0.7/revocation}).
 *
 * <p>One test PKI under its own root: {@code root.der} ("APRV Revocation Test
 * Root", serial 01) issues the WWDR-marked intermediate
 * {@code intermediate.der} (serial 1A), which issues a JWS leaf (serial 02), a
 * receipt leaf (serial 03), a second receipt leaf (serial 04), a JWS leaf with
 * serial zero and one with serial 0x80, whose DER is {@code 00 80}. The other
 * certificates each carry one property a case needs: a second added issuer on
 * no input's path, a revoked one, one sharing the intermediate's key under
 * another name, one under another root, one without {@code cRLSign}, one
 * without the WWDR marker, one that is not a CA, a second root whose name
 * has an RDN SET with two AVAs in non-DER order (with its own intermediate,
 * serial 23, and JWS leaf, serial 05), and a third root with the first one's
 * subject and its own intermediate (serial 1A again). The {@code crl-*.der}
 * files are certificate revocation lists, each with one property, signed by
 * the intermediate unless the name says otherwise; {@code root-crl-*.der}
 * are signed by the root.</p>
 *
 * <p>Fixed dates make the cases independent of when this runs: certificates
 * are valid from 2024-01-01 to 2050-01-01, every JWS is dated and every
 * receipt created on 2024-08-06T12:00:00Z, a fresh list runs from 2026-11-01
 * to 2026-12-01, a stale one from 2026-01-01 to 2026-02-01, and the root's
 * lists to 2027-01-01. The cases pin their clock at 2026-11-05 unless a case
 * is about the clock.</p>
 *
 * <p>Keys come from a {@code SHA1PRNG} seeded with a constant and every
 * signature is RSA PKCS#1 v1.5 or ECDSA drawing on the same generator, so a
 * run on one JDK writes the same bytes each time; another JDK may draw keys
 * differently, which changes every file and its {@code contentSha256}. Run it
 * the way the "Fixtures" paragraph of the {@code fixtures/cases.json} comment
 * documents for the other generators, then re-hash.</p>
 */
public final class RevocationFixtures {

    private static final String LEAF_OID = "1.2.840.113635.100.6.11.1";
    private static final String WWDR_OID = "1.2.840.113635.100.6.2.1";
    /** IANA's example enterprise number (RFC 5612): an extension no implementation knows. */
    private static final String UNKNOWN_OID_CRL = "1.3.6.1.4.1.32473.1";

    private static final String UNKNOWN_OID_ENTRY = "1.3.6.1.4.1.32473.2";

    private static final Date NOT_BEFORE = date("2024-01-01T00:00:00Z");
    private static final Date NOT_AFTER = date("2050-01-01T00:00:00Z");
    private static final long SIGNED_DATE = 1722945600000L; // 2024-08-06T12:00:00Z
    private static final Date SIGNING_TIME = new Date(SIGNED_DATE);
    private static final String CREATION_DATE = "2024-08-06T12:00:00Z";

    private static final Date FRESH_THIS = date("2026-11-01T00:00:00Z");
    private static final Date FRESH_NEXT = date("2026-12-01T00:00:00Z");
    private static final Date STALE_THIS = date("2026-01-01T00:00:00Z");
    private static final Date STALE_NEXT = date("2026-02-01T00:00:00Z");
    private static final Date ROOT_NEXT = date("2027-01-01T00:00:00Z");
    private static final Date REVOKED_AT = date("2026-10-15T00:00:00Z");

    private static final String URL_ROOT_HTTP = "http://crl.example.test/aprv-test-root.crl";
    private static final String URL_ROOT_HTTPS = "https://crl.example.test/aprv-test-root.crl";
    private static final String URL_ROOT_LDAP = "ldap://ldap.example.test/cn=APRV%20Revocation%20Test%20Root";

    private static final String CLAIMS =
            "{\"bundleId\":\"com.example.app\",\"environment\":\"Sandbox\",\"signedDate\":" + SIGNED_DATE + "}";

    private final Path out;
    private final SecureRandom random;

    private RevocationFixtures(Path out) throws Exception {
        this.out = out;
        this.random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        this.random.setSeed("aprv revocation fixtures, 2026-11-05".getBytes(StandardCharsets.US_ASCII));
    }

    public static void main(String[] args) throws Exception {
        Path out = args.length > 0
                ? Paths.get(args[0])
                : TestFixtures.root().resolve("generated-0.7").resolve("revocation");
        Files.createDirectories(out);
        new RevocationFixtures(out).run();
    }

    private void run() throws Exception {
        // --- the test PKI ----------------------------------------------------
        KeyPair rootKeys = rsa();
        X509Certificate root =
                ca("CN=APRV Revocation Test Root,O=APRV Test", rootKeys, 0x01, null, rootKeys, true, true, false);
        KeyPair interKeys = rsa();
        X509Certificate inter = ca(
                "CN=APRV Revocation Test WWDR CA,O=APRV Test",
                interKeys,
                0x1A,
                root,
                rootKeys,
                true,
                true,
                true,
                URL_ROOT_HTTP,
                URL_ROOT_LDAP,
                null,
                URL_ROOT_HTTPS);
        KeyPair secondKeys = rsa();
        X509Certificate second = ca(
                "CN=APRV Revocation Test Second WWDR CA,O=APRV Test",
                secondKeys,
                0x1B,
                root,
                rootKeys,
                true,
                true,
                true,
                URL_ROOT_HTTP);
        KeyPair revokedKeys = rsa();
        X509Certificate revokedIssuer = ca(
                "CN=APRV Revocation Test Revoked WWDR CA,O=APRV Test",
                revokedKeys,
                0x1C,
                root,
                rootKeys,
                true,
                true,
                true,
                URL_ROOT_HTTP);
        // The intermediate's own key under another name: a different issuer (§2).
        X509Certificate twin = ca(
                "CN=APRV Revocation Test WWDR CA Twin,O=APRV Test",
                interKeys,
                0x1D,
                root,
                rootKeys,
                true,
                true,
                true,
                URL_ROOT_HTTP);
        KeyPair otherRootKeys = rsa();
        X509Certificate otherRoot = ca(
                "CN=APRV Revocation Test Other Root,O=APRV Test",
                otherRootKeys,
                0x01,
                null,
                otherRootKeys,
                true,
                true,
                false);
        KeyPair foreignKeys = rsa();
        X509Certificate foreign = ca(
                "CN=APRV Revocation Test Foreign WWDR CA,O=APRV Test",
                foreignKeys,
                0x1E,
                otherRoot,
                otherRootKeys,
                true,
                true,
                true);
        KeyPair noCrlSignKeys = rsa();
        X509Certificate noCrlSign = ca(
                "CN=APRV Revocation Test WWDR CA Without cRLSign,O=APRV Test",
                noCrlSignKeys,
                0x1F,
                root,
                rootKeys,
                true,
                false,
                true);
        KeyPair noMarkerKeys = rsa();
        X509Certificate noMarker = ca(
                "CN=APRV Revocation Test CA Without Marker,O=APRV Test",
                noMarkerKeys,
                0x20,
                root,
                rootKeys,
                true,
                true,
                false);
        KeyPair notCaKeys = rsa();
        X509Certificate notCa = ca(
                "CN=APRV Revocation Test WWDR Not A CA,O=APRV Test",
                notCaKeys,
                0x21,
                root,
                rootKeys,
                false,
                true,
                true);
        KeyPair unknownKeys = rsa();
        X509Certificate unknown = ca(
                "CN=APRV Revocation Test Unknown CA,O=APRV Test",
                unknownKeys,
                0x01,
                null,
                unknownKeys,
                true,
                true,
                false);

        KeyPair jwsKeys = ec();
        X509Certificate jwsLeaf =
                leaf("CN=APRV Revocation Test JWS Signing,O=APRV Test", jwsKeys, 0x02, inter, interKeys);
        KeyPair receiptKeys = rsa();
        X509Certificate receiptLeaf =
                leaf("CN=APRV Revocation Test Receipt Signing,O=APRV Test", receiptKeys, 0x03, inter, interKeys);
        KeyPair receiptTwoKeys = rsa();
        X509Certificate receiptTwoLeaf =
                leaf("CN=APRV Revocation Test Receipt Signing Two,O=APRV Test", receiptTwoKeys, 0x04, inter, interKeys);
        KeyPair zeroKeys = ec();
        X509Certificate zeroLeaf =
                leaf("CN=APRV Revocation Test JWS Signing Serial 00,O=APRV Test", zeroKeys, 0x00, inter, interKeys);
        KeyPair eightyKeys = ec();
        X509Certificate eightyLeaf =
                leaf("CN=APRV Revocation Test JWS Signing Serial 80,O=APRV Test", eightyKeys, 0x80, inter, interKeys);

        write("root.der", root.getEncoded());
        write("intermediate.der", inter.getEncoded());
        write("intermediate-second.der", second.getEncoded());
        write("intermediate-revoked.der", revokedIssuer.getEncoded());
        write("intermediate-same-key-other-name.der", twin.getEncoded());
        write("intermediate-under-another-root.der", foreign.getEncoded());
        write("intermediate-without-crl-sign.der", noCrlSign.getEncoded());
        write("intermediate-without-marker.der", noMarker.getEncoded());
        write("intermediate-not-a-ca.der", notCa.getEncoded());

        // --- signed inputs ---------------------------------------------------
        write("jws.jws", ascii(jws(CLAIMS, jwsKeys.getPrivate(), jwsLeaf, inter, root)));
        write("jws-payload-not-json.jws", ascii(jws("not json", jwsKeys.getPrivate(), jwsLeaf, inter, root)));
        write("jws-serial-00.jws", ascii(jws(CLAIMS, zeroKeys.getPrivate(), zeroLeaf, inter, root)));
        write("jws-serial-80.jws", ascii(jws(CLAIMS, eightyKeys.getPrivate(), eightyLeaf, inter, root)));

        byte[] payload = TestPki.receiptPayload(
                "com.example.app",
                "1.0",
                new byte[] {1, 2, 3, 4},
                new byte[20],
                CREATION_DATE,
                Collections.<byte[]>emptyList());
        write(
                "receipt.der",
                receipt(
                        payload,
                        Collections.singletonList(receiptKeys.getPrivate()),
                        Collections.singletonList(receiptLeaf),
                        Arrays.asList(receiptLeaf, inter, root)));
        byte[] twoSigners = receipt(
                payload,
                Arrays.asList(receiptKeys.getPrivate(), receiptTwoKeys.getPrivate()),
                Arrays.asList(receiptLeaf, receiptTwoLeaf),
                Arrays.asList(receiptLeaf, receiptTwoLeaf, inter, root));
        write("receipt-two-signers.der", twoSigners);
        // DER sorts the SignerInfo SET, so which signer comes first is read back, not chosen.
        BigInteger firstSigner = ((SignerInformation) new CMSSignedData(twoSigners)
                        .getSignerInfos()
                        .getSigners()
                        .iterator()
                        .next())
                .getSID()
                .getSerialNumber();
        System.out.println("receipt-two-signers.der: first SignerInfo is serial " + hex(firstSigner));

        // A root whose subject has one RDN SET of two AVAs in non-DER order (§2), and a chain under it. Only
        // the anchor carries the odd Name: a certificate below it is checked against its signature, and a
        // decoder that re-encodes its TBS in DER (BouncyCastle does) would sort the SET and break that
        // signature, which is a question about reading certificates, not about issuer ids. The
        // intermediate's issuer field holds the Name in DER order, which names the same root.
        KeyPair oddRootKeys = rsa();
        X500NameBuilder oddName = new X500NameBuilder(BCStyle.INSTANCE);
        // Values of one length, so the two AVAs differ first at the OID: DER puts CN (2.5.4.3) first.
        oddName.addMultiValuedRDN(
                new ASN1ObjectIdentifier[] {BCStyle.CN, BCStyle.O}, new String[] {"APRV Odd Root", "APRV Test Org"});
        oddName.addRDN(BCStyle.C, "US");
        X509Certificate oddRootSorted = ca(oddName.build(), oddRootKeys, 0x01, null, oddRootKeys, true, true, false);
        byte[] sortedName = slice(oddRootSorted.getEncoded(), tbsField(oddRootSorted.getEncoded(), SUBJECT));
        byte[] unsortedName = swapFirstTwoAvaRdn(sortedName);
        X509Certificate oddRoot = cert(resign(
                replaceTbsField(
                        replaceTbsField(oddRootSorted.getEncoded(), SUBJECT, unsortedName), ISSUER, unsortedName),
                oddRootKeys.getPrivate(),
                "SHA256withRSA"));
        oddRoot.verify(oddRootKeys.getPublic());
        KeyPair oddInterKeys = rsa();
        X509Certificate oddInter = ca(
                "CN=APRV Revocation Test WWDR CA Under Odd Root,O=APRV Test",
                oddInterKeys,
                0x23,
                oddRootSorted,
                oddRootKeys,
                true,
                true,
                true);
        KeyPair oddLeafKeys = ec();
        X509Certificate oddLeaf = leaf(
                "CN=APRV Revocation Test JWS Signing Under Odd Root,O=APRV Test",
                oddLeafKeys,
                0x05,
                oddInter,
                oddInterKeys);
        write("root-name-avas-not-in-der-order.der", oddRoot.getEncoded());
        write(
                "jws-under-root-name-avas-not-in-der-order.jws",
                ascii(jws(CLAIMS, oddLeafKeys.getPrivate(), oddLeaf, oddInter, oddRoot)));
        System.out.println("odd-name root issuer id, its own bytes: " + issuerId(oddRoot.getEncoded()));
        System.out.println("odd-name root issuer id, name re-encoded in DER order: "
                + hex(sha256(concat(sortedName, slice(oddRoot.getEncoded(), tbsField(oddRoot.getEncoded(), SPKI))))));

        // A second root with the first root's subject, and its own intermediate with serial 1A again.
        KeyPair namesakeKeys = rsa();
        X509Certificate namesake = ca(
                "CN=APRV Revocation Test Root,O=APRV Test", namesakeKeys, 0x02, null, namesakeKeys, true, true, false);
        KeyPair namesakeInterKeys = rsa();
        X509Certificate namesakeInter = ca(
                "CN=APRV Revocation Test WWDR CA Under Namesake Root,O=APRV Test",
                namesakeInterKeys,
                0x1A,
                namesake,
                namesakeKeys,
                true,
                true,
                true);
        KeyPair namesakeLeafKeys = ec();
        X509Certificate namesakeLeaf = leaf(
                "CN=APRV Revocation Test JWS Signing Under Namesake Root,O=APRV Test",
                namesakeLeafKeys,
                0x06,
                namesakeInter,
                namesakeInterKeys);
        write("root-namesake.der", namesake.getEncoded());
        write(
                "jws-under-namesake-root.jws",
                ascii(jws(CLAIMS, namesakeLeafKeys.getPrivate(), namesakeLeaf, namesakeInter, namesake)));

        // --- lists signed by the intermediate --------------------------------
        BigInteger jwsSerial = jwsLeaf.getSerialNumber();
        write("crl-fresh-empty.der", list(inter, interKeys).number(10).build());
        write(
                "crl-fresh-revokes-leaves.der",
                list(inter, interKeys)
                        .number(11)
                        .entry(new Entry(jwsSerial)
                                .reason(CRLReason.keyCompromise)
                                .invalidity())
                        .entry(new Entry(receiptLeaf.getSerialNumber()))
                        .entry(new Entry(receiptTwoLeaf.getSerialNumber()).reason(CRLReason.superseded))
                        .entry(new Entry(zeroLeaf.getSerialNumber()).reason(CRLReason.cessationOfOperation))
                        .entry(new Entry(eightyLeaf.getSerialNumber()).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-stale-revokes-leaves.der",
                list(inter, interKeys)
                        .number(5)
                        .times(STALE_THIS, STALE_NEXT)
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .entry(new Entry(receiptLeaf.getSerialNumber()).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-stale-empty.der",
                list(inter, interKeys).number(4).times(STALE_THIS, STALE_NEXT).build());
        write(
                "crl-certificate-hold.der",
                list(inter, interKeys)
                        .number(12)
                        .entry(new Entry(jwsSerial).reason(CRLReason.certificateHold))
                        .build());
        write(
                "crl-remove-from-crl.der",
                list(inter, interKeys)
                        .number(13)
                        .entry(new Entry(jwsSerial).reason(CRLReason.removeFromCRL))
                        .build());
        write(
                "crl-number-20-revokes.der",
                list(inter, interKeys)
                        .number(20)
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-number-21-earlier-empty.der",
                list(inter, interKeys)
                        .number(21)
                        .times(date("2026-10-01T00:00:00Z"), date("2026-12-15T00:00:00Z"))
                        .build());
        write(
                "crl-number-30-earlier-revokes.der",
                list(inter, interKeys)
                        .number(30)
                        .times(date("2026-10-01T00:00:00Z"), date("2026-11-30T00:00:00Z"))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-no-number-earlier-revokes.der",
                list(inter, interKeys)
                        .times(date("2026-10-01T00:00:00Z"), date("2026-11-30T00:00:00Z"))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-no-number-later-empty.der",
                list(inter, interKeys)
                        .times(date("2026-11-02T00:00:00Z"), date("2026-12-02T00:00:00Z"))
                        .build());
        Date tieThis = date("2026-11-03T00:00:00Z");
        Date tieNext = date("2026-12-03T00:00:00Z");
        write(
                "crl-tie-revokes.der",
                list(inter, interKeys)
                        .times(tieThis, tieNext)
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-tie-empty.der",
                list(inter, interKeys).times(tieThis, tieNext).build());
        write(
                "crl-sha1-revokes.der",
                list(inter, interKeys)
                        .number(14)
                        .algorithm("SHA1withRSA")
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());

        // Genuine lists outside the profile: ignored, not refused (§4).
        write(
                "crl-ignored-v1-revokes.der",
                list(inter, interKeys).v1().noAki().entry(new Entry(jwsSerial)).build());
        write(
                "crl-ignored-no-next-update-revokes.der",
                list(inter, interKeys)
                        .number(15)
                        .times(FRESH_THIS, null)
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-ignored-idp-revokes.der",
                list(inter, interKeys)
                        .number(16)
                        .extension(
                                Extension.issuingDistributionPoint,
                                true,
                                new IssuingDistributionPoint(
                                        new DistributionPointName(new GeneralNames(new GeneralName(
                                                GeneralName.uniformResourceIdentifier,
                                                "http://crl.example.test/aprv-test-wwdr.crl"))),
                                        false,
                                        false,
                                        null,
                                        false,
                                        false))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-ignored-delta-revokes.der",
                list(inter, interKeys)
                        .number(17)
                        .extension(Extension.deltaCRLIndicator, true, new CRLNumber(BigInteger.valueOf(11)))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-ignored-freshest-crl-revokes.der",
                list(inter, interKeys)
                        .number(18)
                        .extension(Extension.freshestCRL, false, new CRLDistPoint(new DistributionPoint[] {
                            new DistributionPoint(
                                    new DistributionPointName(new GeneralNames(new GeneralName(
                                            GeneralName.uniformResourceIdentifier,
                                            "http://crl.example.test/aprv-test-wwdr-delta.crl"))),
                                    null,
                                    null)
                        }))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-ignored-critical-extension-revokes.der",
                list(inter, interKeys)
                        .number(19)
                        .extension(new ASN1ObjectIdentifier(UNKNOWN_OID_CRL), true, DERNull.INSTANCE)
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-ignored-critical-entry-extension-revokes.der",
                list(inter, interKeys)
                        .number(22)
                        .entry(new Entry(jwsSerial)
                                .reason(CRLReason.keyCompromise)
                                .criticalUnknown())
                        .build());
        write(
                "crl-ignored-indirect-entry-revokes.der",
                list(inter, interKeys)
                        .number(23)
                        .entry(new Entry(jwsSerial)
                                .reason(CRLReason.keyCompromise)
                                .certificateIssuer(X500Name.getInstance(
                                        inter.getSubjectX500Principal().getEncoded())))
                        .build());
        write(
                "crl-ignored-duplicate-serial-revokes.der",
                list(inter, interKeys)
                        .number(24)
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());

        // Lists that cannot be attributed to a configured issuer: refused (§4).
        write(
                "crl-refused-bad-signature.der",
                list(inter, interKeys)
                        .number(25)
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .breakSignature()
                        .build());
        byte[] otherKeyId = new byte[20];
        Arrays.fill(otherKeyId, (byte) 0x5A);
        write(
                "crl-refused-other-key-identifier.der",
                list(inter, interKeys)
                        .number(26)
                        .aki(new AuthorityKeyIdentifier(otherKeyId))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-refused-aki-without-key-identifier.der",
                list(inter, interKeys)
                        .number(27)
                        .aki(new AuthorityKeyIdentifier(
                                new GeneralNames(new GeneralName(X500Name.getInstance(
                                        root.getSubjectX500Principal().getEncoded()))),
                                inter.getSerialNumber()))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-refused-unknown-issuer.der",
                list(unknown, unknownKeys)
                        .number(1)
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        // Signed with the intermediate's key, in the name of the twin that shares it.
        write(
                "crl-same-key-other-name-revokes.der",
                list(twin, interKeys)
                        .number(28)
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        // A certificate is DER but not a CertificateList.
        write("crl-refused-not-a-crl.der", inter.getEncoded());
        write(
                "crl-revokes-first-signer.der",
                list(inter, interKeys)
                        .number(29)
                        .entry(new Entry(firstSigner).reason(CRLReason.keyCompromise))
                        .build());

        // --- lists of the other issuers ---------------------------------------
        write(
                "crl-second-issuer-stale-empty.der",
                list(second, secondKeys).number(1).times(STALE_THIS, STALE_NEXT).build());
        write(
                "root-crl-empty.der",
                list(root, rootKeys).number(1).times(FRESH_THIS, ROOT_NEXT).build());
        write(
                "root-crl-revokes-intermediate.der",
                list(root, rootKeys)
                        .number(2)
                        .times(FRESH_THIS, ROOT_NEXT)
                        .entry(new Entry(inter.getSerialNumber()).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "root-crl-revokes-revoked-issuer.der",
                list(root, rootKeys)
                        .number(3)
                        .times(FRESH_THIS, ROOT_NEXT)
                        .entry(new Entry(revokedIssuer.getSerialNumber()).reason(CRLReason.keyCompromise))
                        .build());
        // In the shared root name, without an AuthorityKeyIdentifier, signed by the namesake root.
        write(
                "root-namesake-crl-revokes-1a.der",
                list(namesake, namesakeKeys)
                        .number(1)
                        .times(FRESH_THIS, ROOT_NEXT)
                        .noAki()
                        .entry(new Entry(BigInteger.valueOf(0x1A)).reason(CRLReason.keyCompromise))
                        .build());

        // --- added after the first release of these fixtures ---------------------
        // Everything below uses no randomness (existing keys, RSA signatures), so the
        // files above keep their bytes.

        // Extensions that appear twice, or whose value does not read (§4): a CRL Number that is
        // repeated, negative or not an INTEGER puts the list outside the profile; a reasonCode that is
        // repeated or not an ENUMERATED does not read, so the entry revokes, even where the value
        // spells removeFromCRL; an unknown non-critical extension, repeated, changes nothing.
        write(
                "crl-ignored-repeated-crl-number-revokes.der",
                list(inter, interKeys)
                        .number(31)
                        .raw(extension(Extension.cRLNumber, false, new ASN1Integer(32)))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-ignored-negative-crl-number-revokes.der",
                list(inter, interKeys)
                        .raw(extension(Extension.cRLNumber, false, new ASN1Integer(-1)))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-ignored-unreadable-crl-number-revokes.der",
                list(inter, interKeys)
                        .raw(extension(Extension.cRLNumber, false, new DERUTF8String("33")))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-reason-code-integer-revokes.der",
                list(inter, interKeys)
                        .number(34)
                        .entry(new Entry(jwsSerial)
                                .raw(extension(Extension.reasonCode, false, new ASN1Integer(CRLReason.removeFromCRL))))
                        .build());
        write(
                "crl-repeated-reason-code-revokes.der",
                list(inter, interKeys)
                        .number(35)
                        .entry(new Entry(jwsSerial)
                                .reason(CRLReason.removeFromCRL)
                                .raw(extension(Extension.reasonCode, false, CRLReason.lookup(CRLReason.removeFromCRL))))
                        .build());
        write(
                "crl-repeated-unknown-extension-revokes.der",
                list(inter, interKeys)
                        .number(36)
                        .raw(extension(new ASN1ObjectIdentifier(UNKNOWN_OID_CRL), false, DERNull.INSTANCE))
                        .raw(extension(new ASN1ObjectIdentifier(UNKNOWN_OID_CRL), false, DERNull.INSTANCE))
                        .entry(new Entry(jwsSerial)
                                .reason(CRLReason.keyCompromise)
                                .raw(extension(new ASN1ObjectIdentifier(UNKNOWN_OID_ENTRY), false, DERNull.INSTANCE))
                                .raw(extension(new ASN1ObjectIdentifier(UNKNOWN_OID_ENTRY), false, DERNull.INSTANCE)))
                        .build());

        // The root's list naming the revoked issuer (1C) on hold, or removed (§6: with no clock, a hold
        // counts against an issuer; removeFromCRL does not).
        write(
                "root-crl-holds-revoked-issuer.der",
                list(root, rootKeys)
                        .number(4)
                        .times(FRESH_THIS, ROOT_NEXT)
                        .entry(new Entry(revokedIssuer.getSerialNumber()).reason(CRLReason.certificateHold))
                        .build());
        write(
                "root-crl-removes-revoked-issuer.der",
                list(root, rootKeys)
                        .number(5)
                        .times(FRESH_THIS, ROOT_NEXT)
                        .entry(new Entry(revokedIssuer.getSerialNumber()).reason(CRLReason.removeFromCRL))
                        .build());

        // An issuer the root signed whose issuer Name spells the root's subject with PrintableString
        // where the root's subject has UTF8String: the same name to a canonical comparison, other
        // bytes (§6 compares them byte for byte). It reuses the second issuer's key.
        X509Certificate otherSpelling = ca(
                "CN=APRV Revocation Test WWDR CA Other Issuer Spelling,O=APRV Test",
                secondKeys,
                0x24,
                root,
                rootKeys,
                true,
                true,
                true,
                URL_ROOT_HTTP);
        byte[] printableRootName = new DERSequence(new ASN1Encodable[] {
                    new DERSet(new DERSequence(
                            new ASN1Encodable[] {BCStyle.CN, new DERPrintableString("APRV Revocation Test Root")})),
                    new DERSet(new DERSequence(new ASN1Encodable[] {BCStyle.O, new DERPrintableString("APRV Test")}))
                })
                .getEncoded("DER");
        if (Arrays.equals(printableRootName, root.getSubjectX500Principal().getEncoded())) {
            throw new IllegalStateException("the root's subject is already PrintableString");
        }
        X509Certificate otherSpellingResigned = cert(resign(
                replaceTbsField(otherSpelling.getEncoded(), ISSUER, printableRootName),
                rootKeys.getPrivate(),
                "SHA256withRSA"));
        otherSpellingResigned.verify(rootKeys.getPublic());
        write("intermediate-issuer-name-other-spelling.der", otherSpellingResigned.getEncoded());

        // Extension values with two octets left after the value (§4): such a value is not the DER of its
        // type, so it does not read, even where its leading value would. A reasonCode that spells
        // removeFromCRL revokes; a CRL Number puts the list outside the profile; an AuthorityKeyIdentifier
        // refuses the list; an issuer's SubjectKeyIdentifier makes it no candidate for a list that names
        // its key; an issuer's cRLDistributionPoints names no URL.
        byte[] trailing = {0, 0};
        write(
                "crl-reason-code-trailing-octets-revokes.der",
                list(inter, interKeys)
                        .number(37)
                        .entry(new Entry(jwsSerial)
                                .raw(new Extension(
                                        Extension.reasonCode,
                                        false,
                                        concat(
                                                CRLReason.lookup(CRLReason.removeFromCRL)
                                                        .getEncoded("DER"),
                                                trailing))))
                        .build());
        write(
                "crl-ignored-crl-number-trailing-octets-revokes.der",
                list(inter, interKeys)
                        .raw(new Extension(
                                Extension.cRLNumber, false, concat(new ASN1Integer(38).getEncoded("DER"), trailing)))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        write(
                "crl-refused-aki-trailing-octets.der",
                list(inter, interKeys)
                        .number(39)
                        .noAki()
                        .raw(new Extension(
                                Extension.authorityKeyIdentifier,
                                false,
                                concat(
                                        new JcaX509ExtensionUtils()
                                                .createAuthorityKeyIdentifier(interKeys.getPublic())
                                                .getEncoded("DER"),
                                        trailing)))
                        .entry(new Entry(jwsSerial).reason(CRLReason.keyCompromise))
                        .build());
        // Both reuse the second issuer's key, under names of their own.
        X509Certificate skiTrailing = cert(caWith(
                        "CN=APRV Revocation Test WWDR CA SKI With Trailing Octets,O=APRV Test",
                        secondKeys,
                        0x25,
                        root,
                        rootKeys,
                        new Extension(
                                Extension.subjectKeyIdentifier,
                                false,
                                concat(
                                        new JcaX509ExtensionUtils()
                                                .createSubjectKeyIdentifier(secondKeys.getPublic())
                                                .getEncoded("DER"),
                                        trailing)))
                .getEncoded());
        write("intermediate-ski-trailing-octets.der", skiTrailing.getEncoded());
        write(
                "crl-of-issuer-with-ski-trailing-octets.der",
                list(skiTrailing, secondKeys).number(1).build());
        X509Certificate crldpTrailing = cert(caWith(
                        "CN=APRV Revocation Test WWDR CA CRLDP With Trailing Octets,O=APRV Test",
                        secondKeys,
                        0x26,
                        root,
                        rootKeys,
                        new Extension(
                                Extension.subjectKeyIdentifier,
                                false,
                                new JcaX509ExtensionUtils()
                                        .createSubjectKeyIdentifier(secondKeys.getPublic())
                                        .getEncoded("DER")),
                        new Extension(
                                Extension.cRLDistributionPoints,
                                false,
                                concat(
                                        new CRLDistPoint(new DistributionPoint[] {
                                                    point(Collections.singletonList(new GeneralName(
                                                            GeneralName.uniformResourceIdentifier, URL_ROOT_HTTP)))
                                                })
                                                .getEncoded("DER"),
                                        trailing)))
                .getEncoded());
        write("intermediate-crldp-trailing-octets.der", crldpTrailing.getEncoded());

        // An issuer that meets §6 and also carries a well-formed proxyCertInfo (RFC 3820), which OpenSSL
        // flags as invalid on a CA. §6 asks only for basicConstraints cA, so it is accepted, and its list
        // held. It reuses the second issuer's key under a name of its own.
        X509Certificate proxyInfo = cert(caWith(
                        "CN=APRV Revocation Test WWDR CA With proxyCertInfo,O=APRV Test",
                        secondKeys,
                        0x27,
                        root,
                        rootKeys,
                        new Extension(
                                Extension.subjectKeyIdentifier,
                                false,
                                new JcaX509ExtensionUtils()
                                        .createSubjectKeyIdentifier(secondKeys.getPublic())
                                        .getEncoded("DER")),
                        new Extension(
                                new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.14"),
                                false,
                                new DERSequence(new DERSequence(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.21.1")))
                                        .getEncoded("DER")))
                .getEncoded());
        write("intermediate-with-proxy-cert-info.der", proxyInfo.getEncoded());
        write(
                "crl-of-issuer-with-proxy-cert-info-empty.der",
                list(proxyInfo, secondKeys).number(1).build());

        // Times shorter than RFC 5280's DER forms (§4): a UTCTime without seconds (11 octets) and a
        // GeneralizedTime without its Z (14 octets). OpenSSL refuses a UTCTime under 13 octets and a
        // GeneralizedTime under 15 while decoding, so the list is not a DER CRL and is refused.
        write(
                "crl-refused-short-utc-next-update.der",
                list(inter, interKeys)
                        .number(40)
                        .rawTimes(null, rawTime(0x17, "2612010000Z"))
                        .build());
        write(
                "crl-refused-generalized-this-update-without-zone.der",
                list(inter, interKeys)
                        .number(41)
                        .rawTimes(rawTime(0x18, "20261101000000"), null)
                        .build());
        write(
                "crl-refused-short-utc-revocation-date.der",
                list(inter, interKeys)
                        .number(42)
                        .entry(new Entry(jwsSerial)
                                .reason(CRLReason.keyCompromise)
                                .revocationDate(rawTime(0x17, "2610150000Z")))
                        .build());

        System.out.println("issuer id, root: " + issuerId(root.getEncoded()));
        System.out.println("issuer id, intermediate: " + issuerId(inter.getEncoded()));
        System.out.println("issuer id, twin: " + issuerId(twin.getEncoded()));
        System.out.println("issuer id, namesake root: " + issuerId(namesake.getEncoded()));
    }

    // --- certificates -------------------------------------------------------

    private static final int ISSUER = 3;
    private static final int SUBJECT = 5;
    private static final int SPKI = 6;

    private X509Certificate ca(
            String subject,
            KeyPair keys,
            long serial,
            X509Certificate issuer,
            KeyPair issuerKeys,
            boolean isCa,
            boolean crlSign,
            boolean marker,
            String... distributionPoints)
            throws Exception {
        return ca(new X500Name(subject), keys, serial, issuer, issuerKeys, isCa, crlSign, marker, distributionPoints);
    }

    /**
     * A CA certificate with a SubjectKeyIdentifier, an AuthorityKeyIdentifier
     * unless self-signed, keyUsage keyCertSign (plus cRLSign when asked), and
     * cRLDistributionPoints when {@code distributionPoints} is not empty: a
     * {@code null} in it starts a new DistributionPoint.
     */
    private X509Certificate ca(
            X500Name subject,
            KeyPair keys,
            long serial,
            X509Certificate issuer,
            KeyPair issuerKeys,
            boolean isCa,
            boolean crlSign,
            boolean marker,
            String... distributionPoints)
            throws Exception {
        X500Name issuerName = issuer == null
                ? subject
                : X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, BigInteger.valueOf(serial), NOT_BEFORE, NOT_AFTER, subject, keys.getPublic());
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        builder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(
                        isCa
                                ? KeyUsage.keyCertSign | (crlSign ? KeyUsage.cRLSign : 0)
                                : (crlSign ? KeyUsage.cRLSign : KeyUsage.digitalSignature)));
        builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(keys.getPublic()));
        if (issuer != null) {
            builder.addExtension(
                    Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuer.getPublicKey()));
        }
        if (distributionPoints.length > 0) {
            List<DistributionPoint> points = new ArrayList<DistributionPoint>();
            List<GeneralName> names = new ArrayList<GeneralName>();
            for (String url : distributionPoints) {
                if (url == null) {
                    points.add(point(names));
                    names = new ArrayList<GeneralName>();
                } else {
                    names.add(new GeneralName(GeneralName.uniformResourceIdentifier, url));
                }
            }
            points.add(point(names));
            builder.addExtension(
                    Extension.cRLDistributionPoints, false, new CRLDistPoint(points.toArray(new DistributionPoint[0])));
        }
        if (marker) {
            builder.addExtension(new ASN1ObjectIdentifier(WWDR_OID), false, DERNull.INSTANCE);
        }
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate())));
    }

    /**
     * A WWDR-marked CA certificate (basicConstraints cA, keyUsage
     * keyCertSign and cRLSign, an AuthorityKeyIdentifier) with
     * {@code extensions} written as given, issued by {@code issuer}, as a
     * holder: nothing parses its extensions before it is written.
     */
    private static org.bouncycastle.cert.X509CertificateHolder caWith(
            String subject,
            KeyPair keys,
            long serial,
            X509Certificate issuer,
            KeyPair issuerKeys,
            Extension... extensions)
            throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
                BigInteger.valueOf(serial),
                NOT_BEFORE,
                NOT_AFTER,
                new X500Name(subject),
                keys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuer.getPublicKey()));
        for (Extension extension : extensions) {
            builder.addExtension(extension);
        }
        builder.addExtension(new ASN1ObjectIdentifier(WWDR_OID), false, DERNull.INSTANCE);
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate()));
    }

    private static DistributionPoint point(List<GeneralName> names) {
        return new DistributionPoint(
                new DistributionPointName(new GeneralNames(names.toArray(new GeneralName[0]))), null, null);
    }

    /** A receipt- or JWS-signing leaf: not a CA, the Apple leaf marker, issued by {@code issuer}. */
    private X509Certificate leaf(String subject, KeyPair keys, long serial, X509Certificate issuer, KeyPair issuerKeys)
            throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
                BigInteger.valueOf(serial),
                NOT_BEFORE,
                NOT_AFTER,
                new X500Name(subject),
                keys.getPublic());
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(
                Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuer.getPublicKey()));
        builder.addExtension(new ASN1ObjectIdentifier(LEAF_OID), false, DERNull.INSTANCE);
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate())));
    }

    private KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, random);
        return generator.generateKeyPair();
    }

    private KeyPair ec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), random);
        return generator.generateKeyPair();
    }

    private static X509Certificate cert(byte[] der) throws Exception {
        return (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    // --- signed inputs ------------------------------------------------------

    /** A compact ES256 JWS over {@code payload} with x5c leaf, intermediate, root. */
    private String jws(String payload, PrivateKey key, X509Certificate... chain) throws Exception {
        StringBuilder header = new StringBuilder("{\"alg\":\"ES256\",\"x5c\":[");
        for (int i = 0; i < chain.length; i++) {
            header.append(i == 0 ? "\"" : ",\"")
                    .append(TestPki.b64(chain[i].getEncoded()))
                    .append('"');
        }
        header.append("]}");
        String input = TestPki.b64url(header.toString().getBytes(StandardCharsets.UTF_8)) + "."
                + TestPki.b64url(payload.getBytes(StandardCharsets.UTF_8));
        Signature es256 = Signature.getInstance("SHA256withPLAIN-ECDSA", TestPki.BC);
        es256.initSign(key, random);
        es256.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + TestPki.b64url(es256.sign());
    }

    /** A receipt with one SignerInfo per key, each with a fixed signingTime, embedding {@code embedded}. */
    private static byte[] receipt(
            byte[] payload, List<PrivateKey> keys, List<X509Certificate> signers, List<X509Certificate> embedded)
            throws Exception {
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        for (int i = 0; i < keys.size(); i++) {
            ASN1EncodableVector attributes = new ASN1EncodableVector();
            attributes.add(new org.bouncycastle.asn1.cms.Attribute(
                    CMSAttributes.signingTime, new DERSet(new Time(SIGNING_TIME))));
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                            .setProvider(TestPki.BC)
                            .build())
                    .setSignedAttributeGenerator(
                            new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)))
                    .build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.get(i)), signers.get(i)));
        }
        generator.addCertificates(new JcaCertStore(embedded));
        return generator.generate(new CMSProcessableByteArray(payload), true).getEncoded();
    }

    // --- lists --------------------------------------------------------------

    private CrlSpec list(X509Certificate issuer, KeyPair keys) throws Exception {
        return new CrlSpec(issuer, keys.getPrivate());
    }

    /** One revoked-certificate entry, dated {@link #REVOKED_AT}. */
    private static final class Entry {
        final BigInteger serial;
        CRLReason reason;
        boolean invalidity;
        boolean criticalUnknown;
        X500Name certificateIssuer;
        ASN1Encodable revocationDate;
        final List<ASN1Encodable> raw = new ArrayList<ASN1Encodable>();

        Entry(BigInteger serial) {
            this.serial = serial;
        }

        /** A revocationDate written as given, instead of {@link #REVOKED_AT}. */
        Entry revocationDate(ASN1Encodable time) {
            this.revocationDate = time;
            return this;
        }

        Entry reason(int code) {
            this.reason = CRLReason.lookup(code);
            return this;
        }

        /** A non-critical invalidityDate, before the payloads' date: a revocation ignores dates (§3). */
        Entry invalidity() {
            this.invalidity = true;
            return this;
        }

        Entry criticalUnknown() {
            this.criticalUnknown = true;
            return this;
        }

        Entry certificateIssuer(X500Name name) {
            this.certificateIssuer = name;
            return this;
        }

        /** An Extension written as given, after the others, so an OID can repeat. */
        Entry raw(ASN1Encodable extension) {
            raw.add(extension);
            return this;
        }

        ASN1Encodable encode() throws Exception {
            ASN1EncodableVector entry = new ASN1EncodableVector();
            entry.add(new ASN1Integer(serial));
            entry.add(revocationDate != null ? revocationDate : new Time(REVOKED_AT));
            ExtensionsGenerator extensions = new ExtensionsGenerator();
            if (reason != null) {
                extensions.addExtension(Extension.reasonCode, false, reason);
            }
            if (invalidity) {
                extensions.addExtension(
                        Extension.invalidityDate, false, new ASN1GeneralizedTime(date("2024-01-02T00:00:00Z")));
            }
            if (criticalUnknown) {
                extensions.addExtension(new ASN1ObjectIdentifier(UNKNOWN_OID_ENTRY), true, DERNull.INSTANCE);
            }
            if (certificateIssuer != null) {
                extensions.addExtension(
                        Extension.certificateIssuer, true, new GeneralNames(new GeneralName(certificateIssuer)));
            }
            if (!extensions.isEmpty() || !raw.isEmpty()) {
                entry.add(withRaw(extensions, raw));
            }
            return new DERSequence(entry);
        }
    }

    /**
     * A CertificateList built field by field rather than with
     * X509v2CRLBuilder, so a list can be version 1, lack nextUpdate, carry a
     * duplicate serial or a broken signature. By default: version 2, fresh,
     * an AuthorityKeyIdentifier of the issuer's key, SHA-256 with RSA.
     */
    private final class CrlSpec {
        final X509Certificate issuer;
        final PrivateKey key;
        boolean v1;
        Date thisUpdate = FRESH_THIS;
        Date nextUpdate = FRESH_NEXT;
        BigInteger number;
        AuthorityKeyIdentifier aki;
        boolean withAki = true;
        String algorithm = "SHA256withRSA";
        boolean breakSignature;
        final List<Entry> entries = new ArrayList<Entry>();
        final ExtensionsGenerator extra = new ExtensionsGenerator();
        final List<ASN1Encodable> raw = new ArrayList<ASN1Encodable>();
        ASN1Encodable rawThisUpdate;
        ASN1Encodable rawNextUpdate;

        CrlSpec(X509Certificate issuer, PrivateKey key) {
            this.issuer = issuer;
            this.key = key;
        }

        CrlSpec v1() {
            v1 = true;
            return this;
        }

        CrlSpec number(long n) {
            number = BigInteger.valueOf(n);
            return this;
        }

        CrlSpec times(Date thisUpdate, Date nextUpdate) {
            this.thisUpdate = thisUpdate;
            this.nextUpdate = nextUpdate;
            return this;
        }

        /** thisUpdate and nextUpdate written as given, either null for the default. */
        CrlSpec rawTimes(ASN1Encodable thisUpdate, ASN1Encodable nextUpdate) {
            this.rawThisUpdate = thisUpdate;
            this.rawNextUpdate = nextUpdate;
            return this;
        }

        CrlSpec aki(AuthorityKeyIdentifier aki) {
            this.aki = aki;
            return this;
        }

        CrlSpec noAki() {
            withAki = false;
            return this;
        }

        CrlSpec algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        CrlSpec breakSignature() {
            breakSignature = true;
            return this;
        }

        CrlSpec entry(Entry entry) {
            entries.add(entry);
            return this;
        }

        /** An Extension written as given, after the others, so an OID can repeat. */
        CrlSpec raw(ASN1Encodable extension) {
            raw.add(extension);
            return this;
        }

        CrlSpec extension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) throws Exception {
            extra.addExtension(oid, critical, value);
            return this;
        }

        byte[] build() throws Exception {
            ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(key);
            AlgorithmIdentifier signature = signer.getAlgorithmIdentifier();
            ASN1EncodableVector tbs = new ASN1EncodableVector();
            if (!v1) {
                tbs.add(new ASN1Integer(1));
            }
            tbs.add(signature);
            tbs.add(ASN1Primitive.fromByteArray(issuer.getSubjectX500Principal().getEncoded()));
            tbs.add(rawThisUpdate != null ? rawThisUpdate : new Time(thisUpdate));
            if (rawNextUpdate != null) {
                tbs.add(rawNextUpdate);
            } else if (nextUpdate != null) {
                tbs.add(new Time(nextUpdate));
            }
            if (!entries.isEmpty()) {
                ASN1EncodableVector revoked = new ASN1EncodableVector();
                for (Entry entry : entries) {
                    revoked.add(entry.encode());
                }
                tbs.add(new DERSequence(revoked));
            }
            if (!v1) {
                ExtensionsGenerator extensions = new ExtensionsGenerator();
                if (withAki) {
                    extensions.addExtension(
                            Extension.authorityKeyIdentifier,
                            false,
                            aki != null
                                    ? aki
                                    : new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuer.getPublicKey()));
                }
                if (number != null) {
                    extensions.addExtension(Extension.cRLNumber, false, new CRLNumber(number));
                }
                if (!extra.isEmpty()) {
                    org.bouncycastle.asn1.x509.Extensions added = extra.generate();
                    for (ASN1ObjectIdentifier oid : added.getExtensionOIDs()) {
                        extensions.addExtension(added.getExtension(oid));
                    }
                }
                if (!extensions.isEmpty() || !raw.isEmpty()) {
                    tbs.add(new DERTaggedObject(true, 0, withRaw(extensions, raw)));
                }
            }
            byte[] tbsDer = new DERSequence(tbs).getEncoded("DER");
            OutputStream stream = signer.getOutputStream();
            stream.write(tbsDer);
            stream.close();
            byte[] value = signer.getSignature();
            if (breakSignature) {
                // A middle bit keeps the RSA value below the modulus: the check returns false.
                value[value.length / 2] ^= 0x01;
            }
            ASN1EncodableVector list = new ASN1EncodableVector();
            list.add(ASN1Primitive.fromByteArray(tbsDer));
            list.add(signature);
            list.add(new DERBitString(value));
            byte[] der = new DERSequence(list).getEncoded("DER");
            boolean verifies;
            if (raw.isEmpty()
                    && rawThisUpdate == null
                    && rawNextUpdate == null
                    && entries.stream().allMatch(entry -> entry.raw.isEmpty() && entry.revocationDate == null)) {
                X509CRL parsed =
                        (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(der));
                try {
                    parsed.verify(issuer.getPublicKey());
                    verifies = true;
                } catch (java.security.SignatureException e) {
                    verifies = false;
                }
            } else {
                // A list with an extension or a time written as given may repeat one, or not be DER,
                // which a CRL parser can refuse: check the signature over the TBSCertList directly.
                Signature check = Signature.getInstance(algorithm);
                check.initVerify(issuer.getPublicKey());
                check.update(tbsDer);
                verifies = check.verify(value);
            }
            if (verifies == breakSignature) {
                throw new IllegalStateException("signature check gave " + verifies + " for a list meant to "
                        + (breakSignature ? "fail" : "verify"));
            }
            return der;
        }
    }

    // --- DER plumbing -------------------------------------------------------

    /** A UTCTime (0x17) or GeneralizedTime (0x18) holding {@code text} as given, unchecked. */
    private static ASN1Encodable rawTime(int tag, String text) throws Exception {
        return ASN1Primitive.fromByteArray(tlv(tag, text.getBytes(StandardCharsets.US_ASCII)));
    }

    /** One Extension, encoded as given: an INTEGER where an ENUMERATED belongs, a negative number. */
    private static ASN1Encodable extension(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value)
            throws Exception {
        return new Extension(oid, critical, value.toASN1Primitive().getEncoded("DER"));
    }

    /** The generated Extensions followed by {@code raw}, as one SEQUENCE that may repeat an OID. */
    private static DERSequence withRaw(ExtensionsGenerator generated, List<ASN1Encodable> raw) {
        ASN1EncodableVector all = new ASN1EncodableVector();
        if (!generated.isEmpty()) {
            for (ASN1Encodable extension : org.bouncycastle.asn1.ASN1Sequence.getInstance(
                    generated.generate().toASN1Primitive())) {
                all.add(extension);
            }
        }
        for (ASN1Encodable extension : raw) {
            all.add(extension);
        }
        return new DERSequence(all);
    }

    /** [start, contentStart, end) of the element at {@code at}. */
    private static int[] element(byte[] der, int at) {
        int length = der[at + 1] & 0xff;
        int header = 2;
        if (length >= 0x80) {
            int count = length & 0x7f;
            length = 0;
            for (int i = 0; i < count; i++) {
                length = (length << 8) | (der[at + 2 + i] & 0xff);
            }
            header += count;
        }
        return new int[] {at, at + header, at + header + length};
    }

    private static List<int[]> children(byte[] der, int[] parent) {
        List<int[]> children = new ArrayList<int[]>();
        for (int at = parent[1]; at < parent[2]; ) {
            int[] child = element(der, at);
            children.add(child);
            at = child[2];
        }
        return children;
    }

    /**
     * The TBSCertificate field at {@code index} counted as if the version
     * were always present (0 version, 1 serial, 2 signature, 3 issuer,
     * 4 validity, 5 subject, 6 subjectPublicKeyInfo).
     */
    private static int[] tbsField(byte[] cert, int index) {
        int[] tbs = children(cert, element(cert, 0)).get(0);
        List<int[]> fields = children(cert, tbs);
        boolean hasVersion = (cert[fields.get(0)[0]] & 0xff) == 0xa0;
        return fields.get(hasVersion ? index : index - 1);
    }

    private static byte[] slice(byte[] der, int[] element) {
        return Arrays.copyOfRange(der, element[0], element[2]);
    }

    /** The issuer id of §2: SHA-256 over the subject and the subjectPublicKeyInfo as encoded in the certificate. */
    static String issuerId(byte[] cert) throws Exception {
        return hex(sha256(concat(slice(cert, tbsField(cert, SUBJECT)), slice(cert, tbsField(cert, SPKI)))))
                .toLowerCase();
    }

    /** {@code cert}'s TBS with one Name field replaced by bytes of the same length; the old signature stays. */
    private static byte[] replaceTbsField(byte[] cert, int index, byte[] replacement) {
        int[] field = tbsField(cert, index);
        if (field[2] - field[0] != replacement.length) {
            throw new IllegalStateException("replacement changes the length");
        }
        byte[] patched = cert.clone();
        System.arraycopy(replacement, 0, patched, field[0], replacement.length);
        return patched;
    }

    /** {@code cert} with its TBS signed again by {@code key}, the algorithm identifier kept. */
    private static byte[] resign(byte[] cert, PrivateKey key, String algorithm) throws Exception {
        List<int[]> parts = children(cert, element(cert, 0));
        byte[] tbs = slice(cert, parts.get(0));
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(key);
        signature.update(tbs);
        byte[] value = signature.sign();
        return tlv(0x30, concat(tbs, slice(cert, parts.get(1)), tlv(0x03, concat(new byte[] {0}, value))));
    }

    /** A Name whose first two-AVA RDN SET has its two AVAs swapped (same length, so the Name's length holds). */
    private static byte[] swapFirstTwoAvaRdn(byte[] name) {
        for (int[] rdn : children(name, element(name, 0))) {
            List<int[]> avas = children(name, rdn);
            if (avas.size() == 2) {
                byte[] first = slice(name, avas.get(0));
                byte[] second = slice(name, avas.get(1));
                if (first.length != second.length) {
                    throw new IllegalStateException("AVAs differ in length");
                }
                byte[] swapped = name.clone();
                System.arraycopy(second, 0, swapped, avas.get(0)[0], second.length);
                System.arraycopy(first, 0, swapped, avas.get(1)[0], first.length);
                return swapped;
            }
        }
        throw new IllegalStateException("no RDN with two AVAs");
    }

    private static byte[] tlv(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int length = content.length;
        if (length < 0x80) {
            out.write(length);
        } else if (length < 0x100) {
            out.write(0x81);
            out.write(length);
        } else {
            out.write(0x82);
            out.write(length >> 8);
            out.write(length & 0xff);
        }
        out.write(content, 0, content.length);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.write(part, 0, part.length);
        }
        return out.toByteArray();
    }

    private static byte[] sha256(byte[] bytes) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(bytes);
    }

    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        for (byte b : bytes) {
            text.append(String.format("%02X", b & 0xff));
        }
        return text.toString();
    }

    private static String hex(BigInteger serial) {
        String text = serial.toString(16).toUpperCase();
        return text.length() % 2 == 0 ? text : "0" + text;
    }

    private static Date date(String iso) {
        java.text.SimpleDateFormat format = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        format.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        try {
            return format.parse(iso);
        } catch (java.text.ParseException e) {
            throw new IllegalArgumentException(iso, e);
        }
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    private void write(String name, byte[] bytes) throws Exception {
        Files.write(out.resolve(name), bytes);
        System.out.println(name + "  " + bytes.length + " bytes");
    }
}
