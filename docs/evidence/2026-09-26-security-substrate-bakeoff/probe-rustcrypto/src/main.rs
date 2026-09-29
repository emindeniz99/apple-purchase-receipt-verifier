//! Parses each file given as a CMS ContentInfo, then its SignedData.
//! `.b64` files are base64-decoded first. Prints one line per file.
use base64::Engine;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};

fn main() {
    for path in std::env::args().skip(1) {
        let raw = std::fs::read(&path).expect("read");
        let bytes = if path.ends_with(".b64") {
            let text: String = String::from_utf8_lossy(&raw).split_whitespace().collect();
            base64::engine::general_purpose::STANDARD.decode(text).expect("base64")
        } else {
            raw
        };
        let name = path.rsplit('/').next().unwrap_or(&path);
        match ContentInfo::from_der(&bytes) {
            Err(e) => println!("{name}: ContentInfo error: {e}"),
            Ok(ci) => match ci.content.to_der().and_then(|d| SignedData::from_der(&d)) {
                Err(e) => println!("{name}: SignedData error: {e}"),
                Ok(sd) => println!(
                    "{name}: parsed, {} certificates, {} signer infos",
                    sd.certificates.map_or(0, |c| c.0.len()),
                    sd.signer_infos.0.len()
                ),
            },
        }
    }
}
