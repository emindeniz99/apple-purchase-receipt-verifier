import org.bouncycastle.asn1.ASN1Primitive;

/**
 * How BouncyCastle's ASN.1 parser treats a constructed OCTET STRING whose
 * chunk is not an OCTET STRING: the shape of an eContent re-chunked with a
 * foreign tag. The Java port parses the whole receipt with
 * ASN1Primitive.fromByteArray before CMSSignedData sees it (ReceiptCore),
 * and maps an IOException there to MALFORMED.
 */
public class Probe {
    public static void main(String[] args) {
        byte[][] inputs = {
            // definite length, one OCTET STRING chunk: legal BER
            {0x24, 0x03, 0x04, 0x01, 0x41},
            // definite length, one UTF8String chunk
            {0x24, 0x03, 0x0c, 0x01, 0x41},
            // indefinite length, one UTF8String chunk
            {0x24, (byte) 0x80, 0x0c, 0x01, 0x41, 0x00, 0x00},
        };
        for (byte[] input : inputs) {
            try {
                Object parsed = ASN1Primitive.fromByteArray(input);
                System.out.println("parsed: " + parsed.getClass().getSimpleName());
            } catch (Exception e) {
                System.out.println("refused: " + e);
            }
        }
    }
}
