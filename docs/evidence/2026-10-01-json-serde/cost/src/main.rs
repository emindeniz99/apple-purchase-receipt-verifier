//! Time and peak heap of the old bounded reader and of serde_json on the
//! worst inputs this spike could build within the input caps.
#![allow(dead_code)]

mod old_json;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Peak;

unsafe impl GlobalAlloc for Peak {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
        PEAK.fetch_max(now, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let now = CURRENT.fetch_add(new_size, Ordering::Relaxed) + new_size;
        PEAK.fetch_max(now, Ordering::Relaxed);
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
        p
    }
}

#[global_allocator]
static A: Peak = Peak;

/// (best time in ms, peak heap above the start in bytes, outcome)
fn measure(f: &dyn Fn() -> String) -> (f64, usize, String) {
    let mut best = f64::MAX;
    let mut peak = 0;
    let mut outcome = String::new();
    for _ in 0..5 {
        let base = CURRENT.load(Ordering::Relaxed);
        PEAK.store(base, Ordering::Relaxed);
        let t = Instant::now();
        let out = f();
        best = best.min(t.elapsed().as_secs_f64() * 1e3);
        peak = PEAK.load(Ordering::Relaxed) - base;
        outcome = out;
    }
    (best, peak, outcome)
}

fn old(text: &str, whole: bool) -> String {
    let r = if whole {
        old_json::whole_object_members(text)
    } else {
        old_json::top_level_members(text)
    };
    match r {
        Ok(m) => format!("ok({})", m.len()),
        Err(e) => format!("err({e})"),
    }
}

fn new(text: &str, whole: bool) -> String {
    let r: Result<serde_json::Map<String, serde_json::Value>, _> = if whole {
        serde_json::from_str(text)
    } else {
        match serde_json::Deserializer::from_str(text).into_iter().next() {
            Some(r) => r,
            None => serde_json::from_str(text),
        }
    };
    match r {
        Ok(m) => format!("ok({})", m.len()),
        Err(e) => {
            let s = e.to_string();
            format!("err({})", s.split(" at line").next().unwrap_or(&s))
        }
    }
}

type Raw<'a> = std::collections::BTreeMap<String, &'a serde_json::value::RawValue>;

fn raw(text: &str, whole: bool) -> String {
    let r: Result<Raw<'_>, _> = if whole {
        serde_json::from_str(text)
    } else {
        match serde_json::Deserializer::from_str(text).into_iter().next() {
            Some(r) => r,
            None => serde_json::from_str(text),
        }
    };
    match r {
        Ok(m) => format!("ok({})", m.len()),
        Err(e) => {
            let s = e.to_string();
            format!("err({})", s.split(" at line").next().unwrap_or(&s))
        }
    }
}

/// `{"a":<open>unit<sep>unit...<close>}`, at most `size` bytes.
fn fill(size: usize, open: &str, unit: &str, sep: &str, close: &str) -> String {
    let mut s = format!("{{\"a\":{open}");
    let tail = format!("{close}}}");
    let mut first = true;
    while s.len() + sep.len() + unit.len() + tail.len() <= size {
        if !first {
            s.push_str(sep);
        }
        s.push_str(unit);
        first = false;
    }
    s.push_str(&tail);
    s
}

fn members(size: usize) -> String {
    // {"k0":0,"k1":0,...} distinct names
    let mut s = String::from("{");
    let mut i = 0usize;
    loop {
        let m = format!("\"{i:x}\":0");
        if s.len() + m.len() + 2 > size {
            break;
        }
        if i > 0 {
            s.push(',');
        }
        s.push_str(&m);
        i += 1;
    }
    s.push('}');
    s
}

fn main() {
    const JWS: usize = 196_608; // 256 KiB of base64url, decoded
    const BODY: usize = 3_145_728;
    let cases: Vec<(&str, usize, String)> = [JWS, BODY]
        .into_iter()
        .flat_map(|n| {
            let k = n - 9;
            vec![
                ("long integer", n, format!("{{\"a\":1{}}}", "1".repeat(k))),
                ("long fraction", n, format!("{{\"a\":0.{}}}", "1".repeat(k - 2))),
                ("long exponent", n, format!("{{\"a\":1e{}}}", "1".repeat(k - 2))),
                ("long name", n, format!("{{\"{}\":1}}", "n".repeat(k - 2))),
                ("long string", n, format!("{{\"a\":\"{}\"}}", "s".repeat(k - 2))),
                ("escaped string", n, format!("{{\"a\":\"{}\"}}", "\\u00e9".repeat((k - 2) / 6))),
                ("array of 0", n, fill(n, "[", "0", ",", "]")),
                ("array of {}", n, fill(n, "[", "{}", ",", "]")),
                ("array of []", n, fill(n, "[", "[]", ",", "]")),
                ("array of \"\"", n, fill(n, "[", "\"\"", ",", "]")),
                ("distinct members", n, members(n)),
                ("one name repeated", n, fill(n, "0", ",\"a\":0", "", "")),
                ("array of {\"\":0}", n, fill(n, "[", "{\"\":0}", ",", "]")),
                ("63-deep objects x many", n, fill(n, "[", &format!("{}0{}", "{\"\":".repeat(61), "}".repeat(61)), ",", "]")),
                ("3 MiB deep", n, format!("{{\"a\":{}{}}}", "[".repeat((n - 7) / 2), "]".repeat((n - 7) / 2))),
                ("lone surrogate", n, "{\"a\":\"\\ud800\"}".to_owned()),
                ("127-deep objects x many", n, fill(n, "[", &format!("{}0{}", "{\"\":".repeat(125), "}".repeat(125)), ",", "]")),
                ("127 deep x many", n, fill(n, "[", &format!("{}{}", "[".repeat(125), "]".repeat(125)), ",", "]")),
            ]
        })
        .collect();
    println!("| input | bytes | old ms | old peak | old outcome | Value ms | Value peak | Value outcome | raw ms | raw peak | raw outcome |");
    println!("|---|---:|---:|---:|---|---:|---:|---|---:|---:|---|");
    for (name, n, text) in &cases {
        let whole = *n == JWS;
        let (to, po, oo) = measure(&|| old(text, whole));
        let (tn, pn, on) = measure(&|| new(text, whole));
        let (tr, pr, or) = measure(&|| raw(text, whole));
        println!(
            "| {name} | {} | {to:.2} | {po} | {oo} | {tn:.2} | {pn} | {on} | {tr:.2} | {pr} | {or} |",
            text.len()
        );
    }
}
