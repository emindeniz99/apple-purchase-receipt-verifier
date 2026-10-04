//! Build script for `aprv`:
//!
//! 1. Reads the linked Wasmtime version from `Cargo.lock`.
//! 2. Embeds the precompiled component named by `APRV_CCWASM`, after
//!    checking it against the manifest `aprv precompile` wrote beside it
//!    (`src/manifest.rs`). Without `APRV_CCWASM` the binary embeds nothing
//!    and serves only with `--component` in a `compile` build.
//! 3. Converts `openapi.yaml` to the JSON served at `GET /openapi.json`,
//!    bundling the wire schemas it references from
//!    `../bindings/wire/schema/` so the served document stands alone.

#[path = "src/manifest.rs"]
#[allow(dead_code)]
mod manifest;

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn main() {
    let dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=openapi.yaml");
    println!("cargo:rerun-if-changed=../bindings/wire/schema");
    println!("cargo:rerun-if-env-changed=APRV_CCWASM");

    let wasmtime = wasmtime_version(&dir.join("Cargo.lock"));
    let target = std::env::var("TARGET").unwrap();
    let mut gen = format!("pub const WASMTIME_VERSION: &str = {wasmtime:?};\n");
    gen += &embedded(&target, &wasmtime);
    fs::write(out.join("build_info.rs"), gen).unwrap();

    let openapi = bundle_openapi(&dir);
    fs::write(out.join("openapi.json"), openapi).unwrap();
}

fn wasmtime_version(lock: &Path) -> String {
    let text =
        fs::read_to_string(lock).unwrap_or_else(|e| fail(format!("reading Cargo.lock: {e}")));
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        if l == "name = \"wasmtime\"" {
            if let Some(v) = lines.next().and_then(|v| v.strip_prefix("version = \"")) {
                return v.trim_end_matches('"').to_owned();
            }
        }
    }
    fail("Cargo.lock names no wasmtime package")
}

fn embedded(target: &str, wasmtime: &str) -> String {
    let Some(path) = std::env::var_os("APRV_CCWASM").filter(|p| !p.is_empty()) else {
        return "pub const EMBEDDED: Option<Embedded> = None;\n".into();
    };
    let path = PathBuf::from(path);
    let path = fs::canonicalize(&path)
        .unwrap_or_else(|e| fail(format!("APRV_CCWASM={}: {e}", path.display())));
    println!("cargo:rerun-if-changed={}", path.display());
    let mut mpath = path.clone().into_os_string();
    mpath.push(".json");
    let mpath = PathBuf::from(mpath);
    println!("cargo:rerun-if-changed={}", mpath.display());
    let bytes = fs::read(&path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
    if bytes.starts_with(b"\0asm") {
        fail(format!(
            "APRV_CCWASM={} is a plain .wasm; the shipped build embeds only a file \
             written by `aprv precompile`",
            path.display()
        ));
    }
    let text = fs::read_to_string(&mpath).unwrap_or_else(|e| {
        fail(format!(
            "{}: {e} (`aprv precompile` writes it beside the .ccwasm)",
            mpath.display()
        ))
    });
    let m = manifest::Manifest::from_json(&text)
        .unwrap_or_else(|e| fail(format!("{}: {e}", mpath.display())));
    if let Err(e) = manifest::check(&bytes, &m, target, wasmtime) {
        fail(format!("APRV_CCWASM={}: {e}", path.display()));
    }
    format!(
        "pub const EMBEDDED: Option<Embedded> = Some(Embedded {{\n    bytes: include_bytes!({path:?}),\n    \
         ccwasm_sha256: {:?},\n    component_sha256: {:?},\n    target: {:?},\n    wasm_features: &{:?},\n}});\n",
        m.ccwasm_sha256,
        m.component_sha256,
        m.target,
        m.wasm_features,
        path = path.display().to_string(),
    )
}

/// The wire schemas live in `rust/bindings/wire/schema/` (aprv-wire). The
/// OpenAPI document references them by relative path; the served copy
/// carries them under `components/schemas` so a client needs nothing else.
const SCHEMA_DIR: &str = "../bindings/wire/schema/";

fn bundle_openapi(dir: &Path) -> String {
    let text = fs::read_to_string(dir.join("openapi.yaml"))
        .unwrap_or_else(|e| fail(format!("openapi.yaml: {e}")));
    let mut doc: Value =
        serde_yaml_ng::from_str(&text).unwrap_or_else(|e| fail(format!("openapi.yaml: {e}")));
    let mut refs = Vec::new();
    collect_refs(&doc, &mut refs);
    refs.sort();
    refs.dedup();
    let mut missing = Vec::new();
    for r in &refs {
        let file = &r[SCHEMA_DIR.len()..];
        let name = file.trim_end_matches(".json").trim_end_matches(".schema");
        let path = dir.join(SCHEMA_DIR).join(file);
        println!("cargo:rerun-if-changed={}", path.display());
        let schema = match fs::read_to_string(&path) {
            Ok(s) => embed_schema(
                serde_json::from_str(&s)
                    .unwrap_or_else(|e| fail(format!("{}: {e}", path.display()))),
                name,
            ),
            Err(_) => {
                missing.push(file.to_owned());
                // Present at build time or not, the served document stays
                // valid; a build without the file says so in the schema.
                serde_json::json!({ "description": format!("{file}: not present when this binary was built") })
            }
        };
        doc["components"]["schemas"][name] = schema;
        rewrite_ref(&mut doc, r, &format!("#/components/schemas/{name}"));
    }
    for m in &missing {
        println!("cargo:warning=openapi.json: {SCHEMA_DIR}{m} is missing; the served document carries a placeholder");
    }
    serde_json::to_string(&doc).unwrap()
}

/// A wire schema as the served document carries it, at
/// `#/components/schemas/{name}`. On its own the file is a resource of its
/// own (`$id`), and its `#/$defs/...` references resolve against that
/// resource. Embedded, a resolver that does not treat the `$id` as a new
/// base resolves them against the OpenAPI document, where they lead
/// nowhere (Schemathesis 4.28 skipped the four responses that use them).
/// So the embedded copy drops `$id` and `$schema` (the document's dialect,
/// 2020-12, is the same) and points each local reference at its place in
/// the document, which every resolver follows the same way.
fn embed_schema(mut schema: Value, name: &str) -> Value {
    if let Value::Object(m) = &mut schema {
        m.remove("$id");
        m.remove("$schema");
    }
    anchor_local_refs(&mut schema, &format!("#/components/schemas/{name}"));
    schema
}

fn anchor_local_refs(v: &mut Value, base: &str) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                match x {
                    Value::String(s) if k == "$ref" && s.starts_with("#/") => {
                        *s = format!("{base}{}", &s[1..]);
                    }
                    _ => anchor_local_refs(x, base),
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| anchor_local_refs(x, base)),
        _ => {}
    }
}

fn collect_refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                match x {
                    Value::String(s) if k == "$ref" && s.starts_with(SCHEMA_DIR) => {
                        out.push(s.clone())
                    }
                    _ => collect_refs(x, out),
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| collect_refs(x, out)),
        _ => {}
    }
}

fn rewrite_ref(v: &mut Value, from: &str, to: &str) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if k == "$ref" && x.as_str() == Some(from) {
                    *x = Value::String(to.to_owned());
                } else {
                    rewrite_ref(x, from, to);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| rewrite_ref(x, from, to)),
        _ => {}
    }
}
