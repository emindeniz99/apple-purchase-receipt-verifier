//! aprv-load: keep-alive HTTP/1.1 load generator for the aprv-server spike.
//! One connection per client thread, each request in one write, TCP_NODELAY.
//! Reports throughput, latency percentiles and the server's CPU time (from
//! /proc/<pid>/stat), so "per core" is requests per server CPU-second.
//!
//!   aprv-load --addr 127.0.0.1:PORT --path /v1/receipt/verify --body FILE
//!             --conns C --secs S [--warm N] [--expect TEXT] [--token T] [--pid PID]
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn cpu_ticks(pid: &str) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &s[s.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split(' ').collect();
    Some(f[11].parse::<u64>().ok()? + f[12].parse::<u64>().ok()?) // utime + stime
}

fn rss_kb(pid: &str, key: &str) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines().find(|l| l.starts_with(key))?.split_whitespace().nth(1)?.parse().ok()
}

fn call(s: &mut TcpStream, req: &[u8], buf: &mut Vec<u8>) -> (u16, usize) {
    s.write_all(req).expect("write");
    buf.clear();
    let mut tmp = [0u8; 16384];
    loop {
        let n = s.read(&mut tmp).expect("read");
        assert!(n > 0, "server closed the connection");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(h) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&buf[..h]).unwrap().to_ascii_lowercase();
            let status: u16 = head[9..12].parse().unwrap();
            let cl: usize = head.split("content-length: ").nth(1).unwrap().split("\r\n").next().unwrap().parse().unwrap();
            if buf.len() >= h + 4 + cl {
                return (status, h + 4);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let addr = arg(&args, "--addr").expect("--addr");
    let path = arg(&args, "--path").expect("--path");
    let body = std::fs::read(arg(&args, "--body").expect("--body")).expect("body file");
    let conns: usize = arg(&args, "--conns").map(|v| v.parse().unwrap()).unwrap_or(1);
    let secs: f64 = arg(&args, "--secs").map(|v| v.parse().unwrap()).unwrap_or(10.0);
    let warm: usize = arg(&args, "--warm").map(|v| v.parse().unwrap()).unwrap_or(50);
    let expect = arg(&args, "--expect").unwrap_or_else(|| "\"verified\":true".into());
    let pid = arg(&args, "--pid");
    let token = arg(&args, "--token").map(|t| format!("X-Aprv-Token: {t}\r\n")).unwrap_or_default();
    let mut req = format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{token}Content-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    req.extend_from_slice(&body);
    let req = Arc::new(req);
    let expect = Arc::new(expect);
    {
        let mut s = TcpStream::connect(&addr).unwrap();
        s.set_nodelay(true).unwrap();
        let mut b = vec![];
        for _ in 0..warm {
            let (st, off) = call(&mut s, &req, &mut b);
            assert!(st == 200 && std::str::from_utf8(&b[off..]).unwrap().contains(expect.as_str()), "warm-up: status {st}");
        }
    }
    let stop = Arc::new(AtomicBool::new(false));
    let cpu0 = pid.as_deref().and_then(cpu_ticks);
    let t0 = Instant::now();
    let hs: Vec<_> = (0..conns)
        .map(|_| {
            let (req, expect, stop, addr) = (req.clone(), expect.clone(), stop.clone(), addr.clone());
            std::thread::spawn(move || {
                let mut s = TcpStream::connect(&addr).unwrap();
                s.set_nodelay(true).unwrap();
                let mut b = vec![];
                let mut lat = vec![];
                while !stop.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    let (st, off) = call(&mut s, &req, &mut b);
                    lat.push(t.elapsed().as_secs_f64() * 1e6);
                    assert!(st == 200 && std::str::from_utf8(&b[off..]).unwrap().contains(expect.as_str()), "status {st}");
                }
                lat
            })
        })
        .collect();
    let mut peak_rss = 0;
    while t0.elapsed().as_secs_f64() < secs {
        std::thread::sleep(Duration::from_millis(100));
        if let Some(r) = pid.as_deref().and_then(|p| rss_kb(p, "VmRSS:")) {
            peak_rss = peak_rss.max(r);
        }
    }
    stop.store(true, Ordering::Relaxed);
    let mut lat: Vec<f64> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
    let wall = t0.elapsed().as_secs_f64();
    let cpu1 = pid.as_deref().and_then(cpu_ticks);
    lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)];
    let cpu_s = match (cpu0, cpu1) {
        (Some(a), Some(b)) => (b - a) as f64 / 100.0, // USER_HZ = 100 on Linux
        _ => f64::NAN,
    };
    println!(
        "{{\"path\":\"{path}\",\"conns\":{conns},\"requests\":{},\"wall_s\":{wall:.2},\"req_per_s\":{:.1},\"p50_us\":{:.0},\"p90_us\":{:.0},\"p99_us\":{:.0},\"server_cpu_s\":{cpu_s:.2},\"per_server_cpu_s\":{:.1},\"server_rss_peak_kb\":{peak_rss}}}",
        lat.len(),
        lat.len() as f64 / wall,
        pct(0.5),
        pct(0.9),
        pct(0.99),
        lat.len() as f64 / cpu_s
    );
}
