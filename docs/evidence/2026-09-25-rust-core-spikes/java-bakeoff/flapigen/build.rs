//! Generates JNI glue (Rust) + Java classes from src/java_glue.rs.in.
use std::{env, path::Path};

use flapigen::{JavaConfig, JavaReachabilityFence, LanguageConfig};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    // jni.h -> Rust, via bindgen (flapigen's generated code expects these names).
    let java_home = env::var("JAVA_HOME").unwrap_or_else(|_| "/usr/lib/jvm/java-21-openjdk-amd64".into());
    let inc = Path::new(&java_home).join("include");
    bindgen::builder()
        .layout_tests(false)
        .header(inc.join("jni.h").to_str().unwrap())
        .clang_arg(format!("-I{}", inc.display()))
        .clang_arg(format!("-I{}", inc.join("linux").display()))
        .generate()
        .expect("bindgen jni.h")
        .write_to_file(Path::new(&out_dir).join("jni_c_header.rs"))
        .unwrap();

    let java_out = Path::new("java").join("gen").join("bakeoff").join("flapigen");
    std::fs::create_dir_all(&java_out).unwrap();
    let java_cfg = JavaConfig::new(
        java_out,
        "bakeoff.flapigen".into(),
    )
    // Reference.reachabilityFence is Java 9+; the classes must also run on Java 8.
    .use_reachability_fence(JavaReachabilityFence::GenerateFence(8));

    let in_src = Path::new("src").join("java_glue.rs.in");
    flapigen::Generator::new(LanguageConfig::JavaConfig(java_cfg))
        .rustfmt_bindings(true)
        .remove_not_generated_files_from_output_directory(true)
        // flapigen emits `public final class X {` with no way to add `implements`;
        // a class-attribute callback is its extension hook for that.
        .register_class_attribute_callback("AutoCloseable", |code, class_name| {
            let needle = format!("public final class {class_name} {{");
            let pos = find(code, needle.as_bytes()).expect("class header");
            let repl = format!(
                "public final class {class_name} implements AutoCloseable {{\n    \
                 /** Frees the native object now (same as {{@code delete()}}). */\n    \
                 @Override public void close() {{ delete(); }}\n"
            );
            code.splice(pos..pos + needle.len(), repl.into_bytes());
        })
        .expand("aprv_flapigen", &in_src, Path::new(&out_dir).join("java_glue.rs"));
    println!("cargo:rerun-if-changed={}", in_src.display());
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
