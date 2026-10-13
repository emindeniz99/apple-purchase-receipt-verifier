//! The core's verdict and time on each receipt the probes dumped with
//! `-Ddump=$SCRATCH/shapes/<name>`, under that receipt's own test root.
//! Copy it into rust/tests/, then:
//!   APRV_SHAPES="$SCRATCH/shapes" cargo test --release --test core_shapes -- --nocapture
use apple_purchase_receipt_verifier::__internal::base64_encode;
use apple_purchase_receipt_verifier::{Config, TrustAnchor, Verifier};
use std::time::Instant;

#[test]
fn core_shapes() {
    let dir = std::env::var("APRV_SHAPES").unwrap();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".der") && !name.ends_with(".root.der"))
        .collect();
    names.sort();
    for name in names {
        let stem = name.trim_end_matches(".der");
        let der = std::fs::read(format!("{dir}/{name}")).unwrap();
        let root = std::fs::read(format!("{dir}/{stem}.root.der")).unwrap();
        let config = Config::builder()
            .roots([TrustAnchor::from_der(&root).unwrap()])
            .build()
            .unwrap();
        let verifier = Verifier::new(config);
        let base64 = base64_encode(&der);
        let mut times = Vec::new();
        let mut verdict = String::new();
        for _ in 0..3 {
            let start = Instant::now();
            let result = verifier.verify_receipt(&base64);
            times.push(start.elapsed().as_millis());
            verdict = match result {
                Ok(_) => "ok".to_string(),
                Err(failure) => format!("{failure:?}"),
            };
        }
        println!("core {stem} der={} ms={times:?} {verdict}", der.len());
    }
}
