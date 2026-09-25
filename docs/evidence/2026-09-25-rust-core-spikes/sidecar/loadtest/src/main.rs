use aprv::{apple_receipt_roots, Environment, VerifyReceiptEndpoint};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;

const CALLS: usize = 4000;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args[1].as_str();
    let threads: usize = args[2].parse().unwrap();
    let b64: String = std::fs::read_to_string(
        "$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64",
    ).unwrap().split_whitespace().collect();
    let body = Arc::new(format!("{{\"receipt-data\":\"{b64}\"}}"));
    let t0;
    let mut hs = vec![];
    match mode {
        "inproc" => {
            let ep = Arc::new(VerifyReceiptEndpoint::builder().environment(Environment::Sandbox)
                .trusted_roots(apple_receipt_roots().to_vec()).build().unwrap());
            eprintln!("{}", &ep.verify_receipt_json(&body)[..80]); for _ in 0..200 { let _ = ep.verify_receipt_json(&body); }
            t0 = Instant::now();
            for _ in 0..threads {
                let (ep, body) = (ep.clone(), body.clone());
                hs.push(std::thread::spawn(move || for _ in 0..CALLS { assert!(ep.verify_receipt_json(&body).ends_with("\"status\":0}")); }));
            }
        }
        "http" => {
            let port: u16 = args[3].parse().unwrap();
            let req = Arc::new(format!("POST /verifyReceipt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body));
            let call = |s: &mut TcpStream, req: &str, buf: &mut Vec<u8>| {
                s.write_all(req.as_bytes()).unwrap();
                buf.clear();
                let mut tmp = [0u8; 8192];
                loop {
                    let n = s.read(&mut tmp).unwrap(); buf.extend_from_slice(&tmp[..n]);
                    if let Some(h) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = std::str::from_utf8(&buf[..h]).unwrap().to_ascii_lowercase();
                        let cl: usize = head.split("content-length: ").nth(1).unwrap().split("\r\n").next().unwrap().parse().unwrap();
                        if buf.len() >= h + 4 + cl { assert!(buf.ends_with(b"\"status\":0}")); return; }
                    }
                }
            };
            { let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap(); s.set_nodelay(true).unwrap(); let mut b = vec![]; for _ in 0..200 { call(&mut s, &req, &mut b); } }
            t0 = Instant::now();
            for _ in 0..threads {
                let req = req.clone();
                hs.push(std::thread::spawn(move || {
                    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap(); s.set_nodelay(true).unwrap();
                    let mut b = vec![]; for _ in 0..CALLS { call(&mut s, &req, &mut b); }
                }));
            }
        }
        _ => panic!(),
    }
    for h in hs { h.join().unwrap(); }
    let secs = t0.elapsed().as_secs_f64();
    println!("{mode} threads={threads} req/s={:.0}", (threads * CALLS) as f64 / secs);
}
