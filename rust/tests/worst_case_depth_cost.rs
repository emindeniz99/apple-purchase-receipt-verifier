//! The depth dimension of the denial-of-service envelope, case by case
//! from Java's `WorstCaseDepthCostTest`.
//!
//! Java's suite pins BouncyCastle's construction budget (64 levels), the
//! one bound its library does not own. The core owns both of its bounds:
//! the envelope walk refuses anything nested deeper than 32 constructed
//! values or holding more than 100,000 values, before OpenSSL decodes a
//! byte (`rust/openssl/src/walk.rs`; DECISIONS.md R20, the rows "An
//! envelope nested 33 deep" and "More than 100,000 values in the
//! envelope"). So every shape below is refused as `MALFORMED` in both
//! implementations, the core's message naming its own bound where Java's
//! names BouncyCastle's. Costs are printed, and `common::pki::BUDGET`
//! explains the bounds.

mod common;

use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Failure, Reason};
use common::pki::{
    best_of, nested_sets, with_bag, SignedDataParts, Synthetic, BUDGET, CAP_DER, FREE_BUDGET,
};
use common::tag;

/// The genuine synthetic receipt's chain and signer infos beside a
/// cap-sized nested-SET tree `depth` deep in the bag: Java's `worstShapeAt`.
fn worst_shape_at(genuine: &SignedDataParts, depth: usize) -> Vec<u8> {
    let mut bag = genuine.certificates.clone();
    bag.push(nested_sets(depth, CAP_DER - 16_384));
    with_bag(genuine, bag)
}

/// Java's `rawSetChain`: `depth` nested SETs as raw TLVs, each holding the
/// deeper chain and an INTEGER, the innermost an empty SET when
/// `empty_innermost` and an INTEGER otherwise.
fn raw_set_chain(depth: usize, empty_innermost: bool) -> Vec<u8> {
    let mut inner = if empty_innermost {
        vec![0x31, 0x00]
    } else {
        vec![0x02, 0x01, 0x07]
    };
    for _ in usize::from(empty_innermost)..depth {
        let mut content = inner;
        content.extend_from_slice(&[0x02, 0x01, 0x01]);
        inner = definite_length(tag::SET, &content);
    }
    inner
}

/// Java's `definiteLength`: the tag, a length in one, two, three or five
/// octets, and the content.
fn definite_length(tag: u8, content: &[u8]) -> Vec<u8> {
    let length = content.len();
    let mut out = vec![tag];
    if length < 128 {
        out.push(u8::try_from(length).unwrap());
    } else {
        let octets: usize = if length < 256 {
            1
        } else if length < 65_536 {
            2
        } else {
            4
        };
        out.push(0x80 | u8::try_from(octets).unwrap());
        out.extend_from_slice(&u32::try_from(length).unwrap().to_be_bytes()[4 - octets..]);
    }
    out.extend_from_slice(content);
    out
}

fn refuse_twice(
    verifier: &apple_purchase_receipt_verifier::Verifier,
    der: &[u8],
) -> (Failure, std::time::Duration) {
    let receipt = base64_encode(der);
    best_of(2, || verifier.verify_receipt(&receipt).unwrap_err())
}

/// Mirrors `theFloorGrowsLinearlyWithNestingDepth`: the cap-sized worst
/// shape at depths 2, 16, 32 and 59.
///
/// Java walks the whole tree and refuses the entry as no certificate,
/// "an embedded certificate is not a valid certificate". The core refuses
/// all four at its envelope walk, by the value budget (100,000) at the
/// shallow depths and the depth bound (32) at the deep ones, before
/// OpenSSL decodes the tree; the reason is the same.
#[test]
fn the_floor_grows_linearly_with_nesting_depth() {
    let synthetic = Synthetic::new();
    let verifier = synthetic.pki.verifier();
    let genuine = SignedDataParts::parse(&synthetic.der);
    for depth in [2, 16, 32, 59] {
        let receipt = worst_shape_at(&genuine, depth);
        let (refused, best) = refuse_twice(&verifier, &receipt);
        eprintln!(
            "cap-sized nested SETs {depth} deep: {} ms ({})",
            best.as_millis(),
            refused.message()
        );
        assert_eq!(refused.reason(), Reason::Malformed, "{refused}");
        assert!(best < BUDGET, "depth {depth} took {best:?}");
    }
}

/// Mirrors `deeperThanTheParsersBudgetIsRefusedForFree`: raw SET chains
/// 65 to 100,000 deep (the deepest 881 KB of pure nesting).
///
/// Java hands them to BouncyCastle's parser directly, since its bound is
/// the parser's. The core's bound is its envelope walk, which runs on
/// every receipt before anything else, so each chain is handed to
/// `verify_receipt` as the receipt itself.
#[test]
fn deeper_than_the_parsers_budget_is_refused_for_free() {
    let verifier = common::receipt_verifier();
    for depth in [65, 200, 1000, 10_000, 100_000] {
        let chain = raw_set_chain(depth, false);
        let (refused, best) = refuse_twice(&verifier, &chain);
        eprintln!(
            "raw chain {depth} deep ({} B): refused in {} ms ({})",
            chain.len(),
            best.as_millis(),
            refused.message()
        );
        assert_eq!(refused.reason(), Reason::Malformed, "{refused}");
        assert!(
            refused.message().contains("nested deeper than 32"),
            "{refused}"
        );
        assert!(best < FREE_BUDGET, "depth {depth} took {best:?}");
    }
}

/// Mirrors `theBudgetsEdgeMovesByOneWithTheInnermostShape`.
///
/// Java's first half pins BouncyCastle's own edge: 65 nested SETs parse
/// when the innermost is empty and are refused when it holds a value.
/// That edge is BouncyCastle's (64 levels) and has no counterpart in the
/// core, whose envelope walk refuses both shapes at 32; the walk's own
/// edge is pinned by `envelope_bounds.rs`
/// (`the_depth_bound_counts_every_constructed_value_of_the_envelope`).
/// The second half carries over: a 65-deep tree in a receipt is refused
/// at the parse, before any of it is walked as a certificate. Java's
/// message is "receipt has trailing or unparseable bytes"; the core's
/// names its depth bound.
#[test]
fn the_budgets_edge_moves_by_one_with_the_innermost_shape() {
    let verifier = common::receipt_verifier();
    for empty_innermost in [true, false] {
        let refused = verifier
            .verify_receipt(&base64_encode(&raw_set_chain(65, empty_innermost)))
            .unwrap_err();
        assert_eq!(refused.reason(), Reason::Malformed, "{refused}");
        assert!(
            refused.message().contains("nested deeper than 32"),
            "{refused}"
        );
    }

    let synthetic = Synthetic::new();
    let genuine = SignedDataParts::parse(&synthetic.der);
    assert!(!worst_shape_at(&genuine, 59).is_empty());
    let over = base64_encode(&worst_shape_at(&genuine, 65));
    let verifier = synthetic.pki.verifier();
    let (refused, cost) = common::pki::timed(|| verifier.verify_receipt(&over).unwrap_err());
    eprintln!(
        "a 65-deep tree in a receipt: refused at the parse in {} ms ({})",
        cost.as_millis(),
        refused.message()
    );
    assert_eq!(refused.reason(), Reason::Malformed, "{refused}");
    assert!(cost < FREE_BUDGET, "took {cost:?}");
}
