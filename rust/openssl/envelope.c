/*
 * A shallow view of a CMS SignedData envelope as OpenSSL ASN.1 templates,
 * used only to count the embedded certificates and the SignerInfos before
 * the envelope is decoded for real.
 *
 * d2i_CMS_ContentInfo decodes every embedded certificate in full, public
 * key included, before the caller can see how many there are, so a receipt
 * that embeds a thousand certificates costs a thousand key decodes before
 * the ten-certificate bound can refuse it. This grammar mirrors the shape
 * of OpenSSL's own CMS_ContentInfo and CMS_SignedData (cms_asn1.c) with
 * every member it does not count left as ANY, which OpenSSL keeps as its
 * raw encoding without looking inside. The adapter (src/cms.rs) decodes
 * with ASN1_item_d2i and frees with ASN1_item_free through
 * APRV_ENVELOPE_it. Declarations only: no code, no tag or length handling.
 *
 *   Envelope    ::= SEQUENCE { contentType OBJECT IDENTIFIER,
 *                              content [0] EXPLICIT SignedData }
 *   SignedData  ::= SEQUENCE { version ANY, digestAlgorithms ANY,
 *                              encapContentInfo ANY,
 *                              certificates [0] IMPLICIT SET OF ANY OPTIONAL,
 *                              crls [1] IMPLICIT SET OF ANY OPTIONAL,
 *                              signerInfos SET OF ANY }
 */
#include <openssl/asn1t.h>

typedef struct {
    ASN1_TYPE *version;
    ASN1_TYPE *digest_algorithms;
    ASN1_TYPE *encapsulated_content;
    STACK_OF(ASN1_TYPE) *certificates;
    STACK_OF(ASN1_TYPE) *crls;
    STACK_OF(ASN1_TYPE) *signer_infos;
} APRV_SIGNED_DATA;

typedef struct {
    ASN1_OBJECT *content_type;
    APRV_SIGNED_DATA *content;
} APRV_ENVELOPE;

ASN1_SEQUENCE(APRV_SIGNED_DATA) = {
    ASN1_SIMPLE(APRV_SIGNED_DATA, version, ASN1_ANY),
    ASN1_SIMPLE(APRV_SIGNED_DATA, digest_algorithms, ASN1_ANY),
    ASN1_SIMPLE(APRV_SIGNED_DATA, encapsulated_content, ASN1_ANY),
    ASN1_IMP_SET_OF_OPT(APRV_SIGNED_DATA, certificates, ASN1_ANY, 0),
    ASN1_IMP_SET_OF_OPT(APRV_SIGNED_DATA, crls, ASN1_ANY, 1),
    ASN1_SET_OF(APRV_SIGNED_DATA, signer_infos, ASN1_ANY)
} ASN1_SEQUENCE_END(APRV_SIGNED_DATA)

ASN1_SEQUENCE(APRV_ENVELOPE) = {
    ASN1_SIMPLE(APRV_ENVELOPE, content_type, ASN1_OBJECT),
    ASN1_EXP(APRV_ENVELOPE, content, APRV_SIGNED_DATA, 0)
} ASN1_SEQUENCE_END(APRV_ENVELOPE)
