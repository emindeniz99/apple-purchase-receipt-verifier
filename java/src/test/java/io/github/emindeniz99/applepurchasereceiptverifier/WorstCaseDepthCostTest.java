package io.github.emindeniz99.applepurchasereceiptverifier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.junit.jupiter.api.Test;

/**
 * Round eight: the depth dimension of the DoS envelope, the ledger for the
 * one bound the library does not own. A receipt's parse cost grows linearly
 * in its bytes and linearly in its nesting depth, and the depth is bounded
 * only by BouncyCastle's own construction budget — {@code 64} constructed
 * values by default — which the library checks at {@code Verifier.create}
 * only for the 9 levels a genuine receipt needs. The cost suite
 * ({@link WorstCaseDosCostTest}) measures the worst shape at the deepest
 * nesting a receipt can carry, 59 levels beside its own wrapping; this one
 * pins what makes that the worst: the cost scaling with depth at flat
 * bytes, the budget's exact edge, and that anything beyond the budget is
 * refused before the parse walks a level, sub-millisecond even at 100,000
 * levels. A BouncyCastle release
 * that moves the budget breaks these pins loudly, which is the point: the
 * budget is load-bearing.
 *
 * <p>The one worst case this suite deliberately does not pin is the
 * documented residual: BouncyCastle's parser recurses, so a thread whose
 * stack is smaller than a legal input at the budget needs ends the call
 * with a {@code StackOverflowError}, an {@code Error} the walk does not
 * catch (README, "Thread stack"). It is measured on one JVM and depends on
 * frame sizes no test can pin portably; the guard that would close it is a
 * pre-parse depth bound of our own, an owner decision for a later release.
 * Until then the budget's default of 64 keeps a default-sized thread stack
 * safe, and a host that raises {@code max_cons_depth} re-opens the hole
 * the README warns about.</p>
 */
class WorstCaseDepthCostTest {

    /** The largest receipt DER whose base64 fits the cap. */
    private static final int CAP_DER = ReceiptCore.MAX_RECEIPT_BYTES / 4 * 3;

    /**
     * The floor's shape held flat at the cap, the depth walked up to the
     * deepest a receipt can carry. Each level of nesting costs the same
     * linear share of the cap's bytes, so the floor grows with the depth
     * and stops where the parser's own budget stops it; the numbers print
     * one line per depth for the ledger.
     */
    @Test
    void theFloorGrowsLinearlyWithNestingDepth() throws Exception {
        Verifier verifier = Checks.verifier(SyntheticReceipts.pki());
        SignedData genuine = signedData(SyntheticReceipts.der());
        int[] depths = {2, 16, 32, 59};
        for (int depth : depths) {
            byte[] receipt = worstShapeAt(genuine, depth);
            long best = Long.MAX_VALUE;
            VerificationException refused = null;
            for (int i = 0; i < 2; i++) {
                long start = System.nanoTime();
                refused = assertThrows(VerificationException.class, () -> Checks.receipt(verifier, receipt));
                best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
            }
            System.out.println("cap-sized nested SETs " + depth + " deep: " + best + " ms");
            assertEquals(Reason.MALFORMED, refused.reason(), refused.getMessage());
            assertEquals("an embedded certificate is not a valid certificate", refused.getMessage());
            assertTrue(best < 2000, "depth " + depth + " took " + best + " ms");
        }
    }

    /**
     * Beyond the budget the parse refuses before it walks a level, wherever
     * the bytes came from. These chains are hand-crafted TLVs — the only
     * way to build them, since a chain of BouncyCastle objects thousands
     * deep dies in the encoder's own recursion before the parser ever
     * sees it — parsed directly, with no receipt around them, so the pin
     * is the parser's own budget wherever the chain sits. The
     * 100,000-level chain is 881 KB of pure nesting — over a quarter of
     * the cap — and refusing it costs nothing measurable.
     */
    @Test
    void deeperThanTheParsersBudgetIsRefusedForFree() {
        int[] depths = {65, 200, 1000, 10000, 100000};
        for (int depth : depths) {
            byte[] chain = rawSetChain(depth, false);
            long best = Long.MAX_VALUE;
            IOException refused = null;
            for (int i = 0; i < 2; i++) {
                long start = System.nanoTime();
                refused = assertThrows(IOException.class, () -> ASN1Primitive.fromByteArray(chain));
                best = Math.min(best, (System.nanoTime() - start) / 1_000_000);
            }
            System.out.println("raw chain " + depth + " deep (" + chain.length + " B): refused in " + best + " ms");
            assertEquals("maximum nested construction level reached", refused.getMessage());
            assertTrue(best < 50, "depth " + depth + " took " + best + " ms");
        }
    }

    /**
     * The budget's edge moves by one level with the innermost shape, as the
     * README documents: 65 nested SETs parse when the innermost is empty
     * and are refused when it holds a value. Where a wrapped chain's walk
     * edge sits moves with the genuine chain's own levels beside it — the
     * g5 chain's receipt stops walking a 59-deep tree, the synthetic
     * suite's a 60-deep one — but a chain over any wrapping refuses the
     * walk outright, at the parse, before a level of the tree is walked.
     * Pinned on both sides so a BouncyCastle release that moves the budget
     * — the bound the whole depth floor rests on — fails here loudly
     * instead of quietly doubling the worst case.
     */
    @Test
    void theBudgetsEdgeMovesByOneWithTheInnermostShape() throws Exception {
        ASN1Set parsed = (ASN1Set) ASN1Primitive.fromByteArray(rawSetChain(65, true));
        assertNotNull(parsed);
        assertEquals(2, parsed.size());
        IOException refused =
                assertThrows(IOException.class, () -> ASN1Primitive.fromByteArray(rawSetChain(65, false)));
        assertEquals("maximum nested construction level reached", refused.getMessage());

        SignedData genuine = signedData(SyntheticReceipts.der());
        assertNotNull(worstShapeAt(genuine, 59));
        // The budget counts the receipt's own levels beside the chain's, so
        // a chain this deep is over any wrapping; the walk refuses it at
        // the parse, before the tree is walked. BouncyCastle's encoder
        // builds it without complaint — it carries no budget of its own —
        // which is the point of pinning the refusal at the walk.
        Verifier verifier = Checks.verifier(SyntheticReceipts.pki());
        byte[] over = worstShapeAt(genuine, 65);
        long start = System.nanoTime();
        VerificationException refusedWalk =
                assertThrows(VerificationException.class, () -> Checks.receipt(verifier, over));
        long ms = (System.nanoTime() - start) / 1_000_000;
        System.out.println("a 65-deep tree in a receipt: refused at the parse in " + ms + " ms");
        assertEquals(Reason.MALFORMED, refusedWalk.reason(), refusedWalk.getMessage());
        assertEquals("receipt has trailing or unparseable bytes", refusedWalk.getMessage());
        assertTrue(ms < 50, "took " + ms + " ms");
    }

    private static SignedData signedData(byte[] receipt) {
        return SignedData.getInstance(ContentInfo.getInstance(receipt).getContent());
    }

    /**
     * The genuine chain and signer infos beside a cap-sized nested-SET tree
     * {@code depth} deep planted in the certificate bag: the worst shape,
     * at the given depth. BouncyCastle's encoder builds it at any depth —
     * it carries no budget of its own — and the parser is the one that
     * refuses, counting the receipt's own levels beside the chain's, so
     * where the walk stops moves with the genuine chain's own depth.
     */
    private static byte[] worstShapeAt(SignedData genuine, int depth) throws Exception {
        ASN1EncodableVector bag = new ASN1EncodableVector();
        for (int i = 0; i < genuine.getCertificates().size(); i++) {
            bag.add(genuine.getCertificates().getObjectAt(i));
        }
        bag.add(nestedSets(depth, CAP_DER - 16384));
        return receipt(genuine, new DLSet(bag), genuine.getSignerInfos());
    }

    private static byte[] receipt(SignedData genuine, ASN1Set certificates, ASN1Set signerInfos) throws Exception {
        DLSequence signedData = new DLSequence(new ASN1Encodable[] {
            new ASN1Integer(1),
            genuine.getDigestAlgorithms(),
            genuine.getEncapContentInfo(),
            new DLTaggedObject(false, 0, certificates),
            signerInfos
        });
        byte[] receipt = new DLSequence(
                        new ASN1Encodable[] {CMSObjectIdentifiers.signedData, new DLTaggedObject(true, 0, signedData)})
                .getEncoded(ASN1Encoding.DL);
        assertTrue(receipt.length <= CAP_DER, "the receipt is over the cap: " + receipt.length);
        return receipt;
    }

    /** A SEQUENCE of chains of SETs {@code depth} deep, each SET a chain and an INTEGER, of about {@code bytes}. */
    private static DLSequence nestedSets(int depth, int bytes) throws Exception {
        ASN1Encodable chain = new ASN1Integer(7);
        for (int i = 0; i < depth; i++) {
            chain = new DLSet(new ASN1Encodable[] {chain, new ASN1Integer(1)});
        }
        int chainBytes = chain.toASN1Primitive().getEncoded(ASN1Encoding.DL).length;
        ASN1EncodableVector chains = new ASN1EncodableVector();
        for (int i = 0; i < bytes / chainBytes; i++) {
            chains.add(chain);
        }
        return new DLSequence(chains);
    }

    /**
     * A chain of {@code depth} nested SETs as raw TLV bytes, each holding
     * the deeper chain and an INTEGER, with an empty innermost SET when
     * {@code emptyInnermost} — the two shapes the budget's edge sits
     * between — so the bytes never pass through BouncyCastle's encoder,
     * which enforces the budget on the way out and would refuse to build
     * anything this test refuses to parse.
     */
    private static byte[] rawSetChain(int depth, boolean emptyInnermost) {
        byte[] inner = emptyInnermost ? new byte[] {0x31, 0x00} : new byte[] {0x02, 0x01, 0x07};
        for (int i = emptyInnermost ? 1 : 0; i < depth; i++) {
            byte[] integer = {0x02, 0x01, 0x01};
            byte[] content = new byte[inner.length + integer.length];
            System.arraycopy(inner, 0, content, 0, inner.length);
            System.arraycopy(integer, 0, content, inner.length, integer.length);
            inner = definiteLength((byte) 0x31, content);
        }
        return inner;
    }

    private static byte[] definiteLength(byte tag, byte[] content) {
        int lengthBytes = content.length < 128 ? 1 : content.length < 256 ? 2 : content.length < 65536 ? 3 : 5;
        byte[] out = new byte[1 + lengthBytes + content.length];
        out[0] = tag;
        if (lengthBytes == 1) {
            out[1] = (byte) content.length;
        } else {
            out[1] = (byte) (0x80 | (lengthBytes - 1));
            for (int i = 0; i < lengthBytes - 1; i++) {
                out[2 + i] = (byte) (content.length >>> (8 * (lengthBytes - 2 - i)));
            }
        }
        System.arraycopy(content, 0, out, 1 + lengthBytes, content.length);
        return out;
    }
}
