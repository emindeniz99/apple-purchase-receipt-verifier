//! The manifest `aprv precompile` writes next to a `.ccwasm`, and the check
//! the build (`build.rs`) runs before it embeds that file. Shared by both,
//! so it depends on `sha2` and `serde_json` only.
//!
//! A precompiled file is native code that Wasmtime runs without validating
//! it, so the build embeds only a file whose manifest says what it is and
//! whose bytes still hash to what the manifest recorded.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The manifest's format tag. A manifest of another format is refused.
pub const FORMAT: &str = "aprv-ccwasm-1";

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// What `aprv precompile` records about the file it wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// SHA-256 of the component `.wasm` the file was compiled from.
    pub component_sha256: String,
    /// SHA-256 of the `.ccwasm` file itself.
    pub ccwasm_sha256: String,
    /// The explicit target triple it was compiled for (the ISA baseline).
    pub target: String,
    /// The Wasmtime version that wrote it.
    pub wasmtime: String,
    /// The Wasm features of the engine that wrote it, sorted.
    pub wasm_features: Vec<String>,
}

impl Manifest {
    #[cfg_attr(not(any(test, feature = "compile")), allow(dead_code))] // aprv precompile
    pub fn to_json(&self) -> String {
        let v = json!({
            "format": FORMAT,
            "component_sha256": self.component_sha256,
            "ccwasm_sha256": self.ccwasm_sha256,
            "target": self.target,
            "wasmtime": self.wasmtime,
            "wasm_features": self.wasm_features,
        });
        let mut s = serde_json::to_string_pretty(&v).expect("a JSON value serializes");
        s.push('\n');
        s
    }

    #[cfg_attr(not(test), allow(dead_code))] // build.rs reads manifests
    pub fn from_json(text: &str) -> Result<Manifest, String> {
        let v: Value =
            serde_json::from_str(text).map_err(|e| format!("manifest is not JSON: {e}"))?;
        if v.get("format").and_then(Value::as_str) != Some(FORMAT) {
            return Err(format!("manifest format is not {FORMAT}"));
        }
        let s = |k: &str| {
            v.get(k)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("manifest has no string {k}"))
        };
        let hex64 = |k: &str| -> Result<String, String> {
            let h = s(k)?;
            if h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                Ok(h)
            } else {
                Err(format!("manifest {k} is not a lowercase SHA-256"))
            }
        };
        let wasm_features = v
            .get("wasm_features")
            .and_then(Value::as_array)
            .ok_or("manifest has no wasm_features list")?
            .iter()
            .map(|f| {
                f.as_str()
                    .map(str::to_owned)
                    .ok_or("a wasm feature is not a string")
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Manifest {
            component_sha256: hex64("component_sha256")?,
            ccwasm_sha256: hex64("ccwasm_sha256")?,
            target: s("target")?,
            wasmtime: s("wasmtime")?,
            wasm_features,
        })
    }
}

/// The build's check of a `.ccwasm` before it is embedded: not a plain
/// `.wasm`, not modified since `aprv precompile` wrote it, compiled for the
/// target being built and by the Wasmtime version being linked.
#[cfg_attr(not(test), allow(dead_code))] // build.rs runs the check
pub fn check(
    bytes: &[u8],
    manifest: &Manifest,
    target: &str,
    wasmtime: &str,
) -> Result<(), String> {
    if bytes.starts_with(b"\0asm") {
        return Err("the file is a plain .wasm, not a precompiled .ccwasm: run \
                    `aprv precompile COMPONENT.wasm --target TRIPLE -o FILE.ccwasm` \
                    with the full build first"
            .into());
    }
    let got = sha256_hex(bytes);
    if got != manifest.ccwasm_sha256 {
        return Err(format!(
            "the file's SHA-256 is {got}, but its manifest recorded {}: \
             it changed after `aprv precompile` wrote it",
            manifest.ccwasm_sha256
        ));
    }
    if manifest.target != target {
        return Err(format!(
            "the file was precompiled for {}, but this build targets {target}",
            manifest.target
        ));
    }
    if manifest.wasmtime != wasmtime {
        return Err(format!(
            "the file was precompiled by Wasmtime {}, but this build links Wasmtime {wasmtime}",
            manifest.wasmtime
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(bytes: &[u8]) -> Manifest {
        Manifest {
            component_sha256: "0".repeat(64),
            ccwasm_sha256: sha256_hex(bytes),
            target: "x86_64-unknown-linux-musl".into(),
            wasmtime: "49.0.1".into(),
            wasm_features: vec!["component_model".into()],
        }
    }

    #[test]
    fn round_trips() {
        let m = manifest(b"ELF");
        assert_eq!(Manifest::from_json(&m.to_json()).unwrap(), m);
    }

    #[test]
    fn accepts_the_file_it_describes() {
        let m = manifest(b"\x7fELF code");
        check(b"\x7fELF code", &m, "x86_64-unknown-linux-musl", "49.0.1").unwrap();
    }

    #[test]
    fn refuses_a_plain_wasm() {
        let wasm = b"\0asm\x0d\0\x01\0";
        let e = check(wasm, &manifest(wasm), "x86_64-unknown-linux-musl", "49.0.1").unwrap_err();
        assert!(e.contains("plain .wasm"), "{e}");
    }

    #[test]
    fn refuses_a_tampered_file() {
        let m = manifest(b"\x7fELF code");
        let e = check(b"\x7fELF cod3", &m, "x86_64-unknown-linux-musl", "49.0.1").unwrap_err();
        assert!(e.contains("changed after"), "{e}");
    }

    #[test]
    fn refuses_another_target_or_wasmtime() {
        let m = manifest(b"x");
        assert!(check(b"x", &m, "aarch64-unknown-linux-musl", "49.0.1")
            .unwrap_err()
            .contains("precompiled for"));
        assert!(check(b"x", &m, "x86_64-unknown-linux-musl", "50.0.0")
            .unwrap_err()
            .contains("Wasmtime 49.0.1"));
    }

    #[test]
    fn refuses_a_malformed_manifest() {
        assert!(Manifest::from_json("{}").is_err());
        let bad = manifest(b"x").to_json().replace(FORMAT, "other");
        assert!(Manifest::from_json(&bad).is_err());
        let bad = manifest(b"x").to_json().replace(&sha256_hex(b"x"), "ABC");
        assert!(Manifest::from_json(&bad).is_err());
    }
}
