//! Reads every file named on the command line with both readers and
//! prints whether they agree: the same DER list, or both refusing.
//! Exits 1 on any disagreement.

mod new;
mod old;

fn main() {
    let (mut same, mut diff) = (0, 0);
    for path in std::env::args().skip(1) {
        let text = std::fs::read_to_string(&path).unwrap();
        let (o, n) = (old::from_file_text(&text), new::from_file_text(&text));
        let agree = match (&o, &n) {
            (Ok(a), Ok(b)) => a == b,
            (Err(_), Err(_)) => true,
            _ => false,
        };
        let show = |r: &Result<Vec<Vec<u8>>, String>| match r {
            Ok(v) => format!("ok, {} roots", v.len()),
            Err(e) => format!("refused: {e}"),
        };
        let name = std::path::Path::new(&path)
            .file_name()
            .unwrap()
            .to_string_lossy();
        println!("{} {name}", if agree { "SAME" } else { "DIFF" });
        println!("    old {}", show(&o));
        println!("    new {}", show(&n));
        if agree {
            same += 1
        } else {
            diff += 1
        }
    }
    println!("same {same}, diff {diff}");
    std::process::exit(i32::from(diff > 0));
}
