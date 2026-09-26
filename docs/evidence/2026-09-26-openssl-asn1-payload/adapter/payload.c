/*
 * Spike only (round 4). Apple's receipt payload grammar as OpenSSL ASN.1
 * templates, the way OpenSSL declares its own structures (x_x509.c,
 * cms_asn1.c). Declarations only: no code, no length or tag handling. The
 * adapter (payload.rs) decodes with ASN1_item_d2i and frees with
 * ASN1_item_free through the item functions these macros define
 * (APRV_RECEIPT_ATTRIBUTE_it, APRV_RECEIPT_PAYLOAD_it).
 *
 *   Payload           ::= SET OF ReceiptAttribute
 *   ReceiptAttribute  ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING }
 *
 * version is declared ANY: the pure-Rust reader never looked at it, and
 * Apple's documentation gives it no meaning.
 *
 * A string-valued attribute (CHOICE { UTF8String, IA5String }) is not
 * declared here: IMPLEMENT_ASN1_MSTRING needs sizeof(ASN1_STRING), and
 * OpenSSL 4.0 made ASN1_STRING opaque, so an MSTRING item can no longer be
 * defined outside libcrypto. payload_templates.rs uses libcrypto's own
 * DISPLAYTEXT item (IA5String, VisibleString, BMPString, UTF8String) and
 * keeps the two types the grammar allows.
 */
#include <openssl/asn1t.h>

typedef struct aprv_receipt_attribute_st {
    ASN1_INTEGER *type;
    ASN1_TYPE *version;
    ASN1_OCTET_STRING *value;
} APRV_RECEIPT_ATTRIBUTE;

ASN1_SEQUENCE(APRV_RECEIPT_ATTRIBUTE) = {
    ASN1_SIMPLE(APRV_RECEIPT_ATTRIBUTE, type, ASN1_INTEGER),
    ASN1_SIMPLE(APRV_RECEIPT_ATTRIBUTE, version, ASN1_ANY),
    ASN1_SIMPLE(APRV_RECEIPT_ATTRIBUTE, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(APRV_RECEIPT_ATTRIBUTE)

ASN1_ITEM_TEMPLATE(APRV_RECEIPT_PAYLOAD) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, Payload, APRV_RECEIPT_ATTRIBUTE)
ASN1_ITEM_TEMPLATE_END(APRV_RECEIPT_PAYLOAD)
