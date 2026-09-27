package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.jupiter.api.Test;

/**
 * The decoder on payloads written here, rather than signed: what a value that
 * does not decode costs. One attribute, never the receipt, so an app server
 * still sees every purchase Apple signed.
 */
class ReceiptDecoderTest {

    /** A UTF8String whose content is not UTF-8: a lead byte, then no continuation. */
    private static final byte[] NOT_UTF8 = {0x0C, 0x02, (byte) 0xC3, 0x28};

    @Test
    void aStringThatIsNotUtf8IsKeptRawTopLevelAndInApp() throws Exception {
        byte[] inApp = set(attribute(1702, NOT_UTF8), attribute(1703, new DERUTF8String("1000").getEncoded()));
        byte[] payload = set(attribute(3, NOT_UTF8), attribute(17, inApp));

        ReceiptPayload receipt = ReceiptDecoder.parse(payload);

        assertNull(receipt.applicationVersion());
        assertArrayEquals(NOT_UTF8, receipt.unknownAttributes().get(3).get(0));
        assertEquals(1, receipt.inApp().size());
        InAppPurchase purchase = receipt.inApp().get(0);
        assertNull(purchase.productId());
        assertArrayEquals(NOT_UTF8, purchase.unknownAttributes().get(1702).get(0));
        // The attribute next to it is untouched.
        assertEquals("1000", purchase.transactionId());
    }

    private static byte[] attribute(int type, byte[] value) throws Exception {
        return new DERSequence(new ASN1Encodable[] {
                    new ASN1Integer(type), new ASN1Integer(1), new DEROctetString(value)
                })
                .getEncoded();
    }

    private static byte[] set(byte[]... attributes) throws Exception {
        ASN1Encodable[] elements = new ASN1Encodable[attributes.length];
        for (int i = 0; i < attributes.length; i++) {
            elements[i] = DERSequence.getInstance(attributes[i]);
        }
        return new DERSet(elements).getEncoded();
    }
}
