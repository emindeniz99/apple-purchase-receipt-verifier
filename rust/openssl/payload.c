/*
 * Apple's receipt payload grammar as OpenSSL ASN.1 templates, declared the
 * way OpenSSL declares its own structures (x_x509.c, cms_asn1.c).
 * Declarations only: no code, no tag or length handling. The adapter
 * (src/payload.rs) decodes with ASN1_item_d2i and frees with
 * ASN1_item_free through the item function this macro defines
 * (APRV_RECEIPT_PAYLOAD_it).
 *
 *   Payload           ::= SET OF ReceiptAttribute
 *   ReceiptAttribute  ::= SEQUENCE { type INTEGER, version INTEGER, value OCTET STRING, ... }
 *
 * The attribute is declared as libcrypto's SEQUENCE OF ANY, and
 * src/payload.rs checks the types of its first three fields. A SEQUENCE
 * template of exactly those three fields would refuse a fourth, which the
 * 0.7 contract requires a reader to accept (fixtures/cases.json,
 * receipt/accept-signed-content-nested-32-deep), and a template cannot say
 * "and whatever follows". Every field is still decoded by OpenSSL by its
 * tag: an INTEGER anywhere must be a valid INTEGER.
 */
#include <openssl/asn1t.h>

ASN1_ITEM_TEMPLATE(APRV_RECEIPT_PAYLOAD) =
    ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, Payload, ASN1_SEQUENCE_ANY)
ASN1_ITEM_TEMPLATE_END(APRV_RECEIPT_PAYLOAD)
