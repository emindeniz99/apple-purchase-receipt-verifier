/*
 * A certificate revocation list (RFC 5280 section 5.1) as OpenSSL ASN.1
 * templates, for the core's revocation lists (docs/design/revocation.md).
 *
 * The grammar is OpenSSL's own X509_CRL_INFO and X509_CRL (x_crl.c), member
 * for member, with the original encoding of the TBSCertList cached
 * (ASN1_SEQUENCE_enc) so the signature is checked over the bytes that were
 * signed. What it leaves out is the post-decode callback of X509_CRL
 * (crl_cb, crl_set_issuers), which interprets the extensions while
 * decoding and makes d2i_X509_CRL refuse some lists outright: in OpenSSL
 * 4.0 an entry with a certificateIssuer extension in a list without an
 * indirect IssuingDistributionPoint. The revocation design ignores such a
 * list rather than refusing it, so the core needs to read it, check its
 * signature and then set it aside; this grammar lets it. Every value is
 * still decoded by OpenSSL's own templates (X509_NAME, ASN1_TIME,
 * X509_REVOKED, X509_EXTENSION), and the adapter (src/crl.rs) reads them
 * with OpenSSL's accessors. Declarations only: no code, no tag or length
 * handling.
 *
 *   CertificateList ::= SEQUENCE { tbsCertList TBSCertList,
 *                                  signatureAlgorithm AlgorithmIdentifier,
 *                                  signatureValue BIT STRING }
 *   TBSCertList ::= SEQUENCE { version INTEGER OPTIONAL,
 *                              signature AlgorithmIdentifier,
 *                              issuer Name,
 *                              thisUpdate Time,
 *                              nextUpdate Time OPTIONAL,
 *                              revokedCertificates SEQUENCE OF ... OPTIONAL,
 *                              crlExtensions [0] EXPLICIT Extensions OPTIONAL }
 *
 * src/sys.rs mirrors both structures' pointer members; the static
 * assertions below and the ones there pin the layout both sides assume.
 * The cached encoding sits after them and is OpenSSL's alone.
 */
#include <stddef.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>

typedef struct {
    ASN1_INTEGER *version;
    X509_ALGOR *signature;
    X509_NAME *issuer;
    ASN1_TIME *this_update;
    ASN1_TIME *next_update;
    STACK_OF(X509_REVOKED) *revoked;
    STACK_OF(X509_EXTENSION) *extensions;
    ASN1_ENCODING enc;
} APRV_TBS_CERT_LIST;

typedef struct {
    APRV_TBS_CERT_LIST *tbs;
    X509_ALGOR *algorithm;
    ASN1_BIT_STRING *signature;
} APRV_CERT_LIST;

_Static_assert(offsetof(APRV_TBS_CERT_LIST, signature) == 1 * sizeof(void *),
               "APRV_TBS_CERT_LIST.signature is the second pointer");
_Static_assert(offsetof(APRV_TBS_CERT_LIST, issuer) == 2 * sizeof(void *),
               "APRV_TBS_CERT_LIST.issuer is the third pointer");
_Static_assert(offsetof(APRV_TBS_CERT_LIST, this_update) == 3 * sizeof(void *),
               "APRV_TBS_CERT_LIST.this_update is the fourth pointer");
_Static_assert(offsetof(APRV_TBS_CERT_LIST, next_update) == 4 * sizeof(void *),
               "APRV_TBS_CERT_LIST.next_update is the fifth pointer");
_Static_assert(offsetof(APRV_TBS_CERT_LIST, revoked) == 5 * sizeof(void *),
               "APRV_TBS_CERT_LIST.revoked is the sixth pointer");
_Static_assert(offsetof(APRV_TBS_CERT_LIST, extensions) == 6 * sizeof(void *),
               "APRV_TBS_CERT_LIST.extensions is the seventh pointer");
_Static_assert(sizeof(APRV_CERT_LIST) == 3 * sizeof(void *),
               "APRV_CERT_LIST is three pointers");
_Static_assert(offsetof(APRV_CERT_LIST, algorithm) == sizeof(void *),
               "APRV_CERT_LIST.algorithm is the second pointer");
_Static_assert(offsetof(APRV_CERT_LIST, signature) == 2 * sizeof(void *),
               "APRV_CERT_LIST.signature is the third pointer");

DECLARE_ASN1_ITEM(APRV_TBS_CERT_LIST)
DECLARE_ASN1_ITEM(APRV_CERT_LIST)

ASN1_SEQUENCE_enc(APRV_TBS_CERT_LIST, enc, 0) = {
    ASN1_OPT(APRV_TBS_CERT_LIST, version, ASN1_INTEGER),
    ASN1_SIMPLE(APRV_TBS_CERT_LIST, signature, X509_ALGOR),
    ASN1_SIMPLE(APRV_TBS_CERT_LIST, issuer, X509_NAME),
    ASN1_SIMPLE(APRV_TBS_CERT_LIST, this_update, ASN1_TIME),
    ASN1_OPT(APRV_TBS_CERT_LIST, next_update, ASN1_TIME),
    ASN1_SEQUENCE_OF_OPT(APRV_TBS_CERT_LIST, revoked, X509_REVOKED),
    ASN1_EXP_SEQUENCE_OF_OPT(APRV_TBS_CERT_LIST, extensions, X509_EXTENSION, 0)
} ASN1_SEQUENCE_END_enc(APRV_TBS_CERT_LIST, APRV_TBS_CERT_LIST)

ASN1_SEQUENCE(APRV_CERT_LIST) = {
    ASN1_SIMPLE(APRV_CERT_LIST, tbs, APRV_TBS_CERT_LIST),
    ASN1_SIMPLE(APRV_CERT_LIST, algorithm, X509_ALGOR),
    ASN1_SIMPLE(APRV_CERT_LIST, signature, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(APRV_CERT_LIST)
