/*
 * A shallow view of a CMS ContentInfo and SignedData as OpenSSL ASN.1
 * templates, used to name the content type and count the embedded
 * certificates and SignerInfos before the envelope is decoded for real.
 *
 * d2i_CMS_ContentInfo decodes every embedded certificate in full, public
 * key included, before the caller can see how many there are, so a receipt
 * that embeds a thousand certificates costs a thousand key decodes before
 * the ten-certificate bound can refuse it. This grammar mirrors the shape
 * of OpenSSL's own CMS_ContentInfo and CMS_SignedData (cms_asn1.c) with
 * every member it does not count left as ANY, which OpenSSL keeps as its
 * raw encoding without looking inside. The adapter (src/envelope.rs)
 * decodes with ASN1_item_d2i and frees with ASN1_item_free through the
 * two item functions declared below. Declarations only: no code, no tag or
 * length handling.
 *
 *   ContentInfo ::= SEQUENCE { contentType OBJECT IDENTIFIER,
 *                              content [0] EXPLICIT ANY }
 *   SignedData  ::= SEQUENCE { version ANY, digestAlgorithms ANY,
 *                              encapContentInfo ANY,
 *                              certificates [0] IMPLICIT SET OF ANY OPTIONAL,
 *                              crls [1] IMPLICIT SET OF ANY OPTIONAL,
 *                              signerInfos SET OF ANY }
 *
 * src/sys.rs mirrors both structures field for field; the static
 * assertions below and the ones there pin the layout both sides assume.
 */
#include <stddef.h>
#include <openssl/asn1t.h>

typedef struct {
    ASN1_OBJECT *content_type;
    ASN1_TYPE *content;
} APRV_CONTENT_INFO;

typedef struct {
    ASN1_TYPE *version;
    ASN1_TYPE *digest_algorithms;
    ASN1_TYPE *encapsulated_content;
    STACK_OF(ASN1_TYPE) *certificates;
    STACK_OF(ASN1_TYPE) *crls;
    STACK_OF(ASN1_TYPE) *signer_infos;
} APRV_SIGNED_DATA;

_Static_assert(sizeof(APRV_CONTENT_INFO) == 2 * sizeof(void *),
               "APRV_CONTENT_INFO is two pointers");
_Static_assert(offsetof(APRV_CONTENT_INFO, content) == sizeof(void *),
               "APRV_CONTENT_INFO.content is the second pointer");
_Static_assert(sizeof(APRV_SIGNED_DATA) == 6 * sizeof(void *),
               "APRV_SIGNED_DATA is six pointers");
_Static_assert(offsetof(APRV_SIGNED_DATA, encapsulated_content) == 2 * sizeof(void *),
               "APRV_SIGNED_DATA.encapsulated_content is the third pointer");
_Static_assert(offsetof(APRV_SIGNED_DATA, certificates) == 3 * sizeof(void *),
               "APRV_SIGNED_DATA.certificates is the fourth pointer");
_Static_assert(offsetof(APRV_SIGNED_DATA, crls) == 4 * sizeof(void *),
               "APRV_SIGNED_DATA.crls is the fifth pointer");
_Static_assert(offsetof(APRV_SIGNED_DATA, signer_infos) == 5 * sizeof(void *),
               "APRV_SIGNED_DATA.signer_infos is the sixth pointer");

DECLARE_ASN1_ITEM(APRV_CONTENT_INFO)
DECLARE_ASN1_ITEM(APRV_SIGNED_DATA)

ASN1_SEQUENCE(APRV_CONTENT_INFO) = {
    ASN1_SIMPLE(APRV_CONTENT_INFO, content_type, ASN1_OBJECT),
    ASN1_EXP(APRV_CONTENT_INFO, content, ASN1_ANY, 0)
} ASN1_SEQUENCE_END(APRV_CONTENT_INFO)

ASN1_SEQUENCE(APRV_SIGNED_DATA) = {
    ASN1_SIMPLE(APRV_SIGNED_DATA, version, ASN1_ANY),
    ASN1_SIMPLE(APRV_SIGNED_DATA, digest_algorithms, ASN1_ANY),
    ASN1_SIMPLE(APRV_SIGNED_DATA, encapsulated_content, ASN1_ANY),
    ASN1_IMP_SET_OF_OPT(APRV_SIGNED_DATA, certificates, ASN1_ANY, 0),
    ASN1_IMP_SET_OF_OPT(APRV_SIGNED_DATA, crls, ASN1_ANY, 1),
    ASN1_SET_OF(APRV_SIGNED_DATA, signer_infos, ASN1_ANY)
} ASN1_SEQUENCE_END(APRV_SIGNED_DATA)
