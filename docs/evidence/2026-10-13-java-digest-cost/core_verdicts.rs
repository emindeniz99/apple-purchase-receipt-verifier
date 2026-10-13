//! The core's verdict on each receipt variants.mjs wrote, under the default
//! roots. Copy it into rust/tests/, then:
//!   APRV_VARIANTS="$SCRATCH/variants" cargo test --test core_verdicts -- --nocapture
use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Config, Verifier};

#[test]
fn core_verdicts() {
    let dir = std::env::var("APRV_VARIANTS").unwrap();
    for name in ["gost94", "md2", "whirlpool", "streebog256", "streebog512", "dstu256", "dstu384", "dstu512"] {
        let der = std::fs::read(format!("{dir}/{name}.der")).unwrap();
        let result = Verifier::new(Config::default()).verify_receipt(&base64_encode(&der));
        println!("core {name}: {:?}", result.err());
    }
}
