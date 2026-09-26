// Spike only (2026-09-26). The harness for aprv.wasm on WasmKit:
//   aprv-tool tests calls-cases.jsonl        the ABI v1 round's 33 ABI tests + the facade's contract
//   aprv-tool calls calls.jsonl              corpus rows in the Node runner's exact format
//   aprv-tool startup calls-cases.jsonl      runtime, first instance, second instance, first and second call (ms)
//   aprv-tool bench calls-cases.jsonl id warm n           one thread, one instance
//   aprv-tool threads calls-cases.jsonl id threads warm n one instance per thread
//   aprv-tool isolation calls-cases.jsonl    independent instances; traps under concurrency
import AprvWasm
import Foundation
import WasmKit

setvbuf(stdout, nil, _IOFBF, 1 << 20)

func loadCalls(_ path: String) -> [[String: Any]] {
    let text = try! String(contentsOfFile: path, encoding: .utf8)
    return text.split(separator: "\n").map { try! JSONSerialization.jsonObject(with: Data($0.utf8)) as! [String: Any] }
}

func call(_ calls: [[String: Any]], _ id: String) -> (UInt32, [UInt8]) {
    let c = calls.first { $0["id"] as? String == id }!
    return (UInt32(c["op"] as! Int), [UInt8](Data(base64Encoded: c["input"] as! String)!))
}

/// A JSON string literal, escaped the way JSON.stringify escapes.
func quote(_ s: String) -> String {
    var out = "\""
    for u in s.unicodeScalars {
        switch u {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        case "\u{08}": out += "\\b"
        case "\u{0C}": out += "\\f"
        default:
            if u.value < 0x20 { out += String(format: "\\u%04x", u.value) } else { out.unicodeScalars.append(u) }
        }
    }
    return out + "\""
}

func now() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1e9 }
func round1(_ x: Double) -> Double { (x * 10).rounded() / 10 }
func isVerified(_ b: [UInt8]) -> Bool { b.starts(with: Array("{\"verified\":true".utf8)) }

let args = CommandLine.arguments
let mode = args[1]
let calls = loadCalls(args[2])

switch mode {
case "calls":
    var inst = try AprvInstance()
    var traps = 0, rows = 0
    for c in calls {
        rows += 1
        let id = quote(c["id"] as! String)
        guard let op = c["op"] as? Int else {
            print("{\"id\":\(id),\"map\":\(quote(c["map"] as! String))}")
            continue
        }
        let input = [UInt8](Data(base64Encoded: c["input"] as! String)!)
        do {
            let out = try inst.invoke(UInt32(op), input)
            print("{\"id\":\(id),\"out\":\(quote(String(decoding: out, as: UTF8.self)))}")
        } catch {
            traps += 1
            inst = try AprvInstance()
            print("{\"id\":\(id),\"trap\":\(quote("\(error)"))}")
        }
    }
    fflush(stdout)
    FileHandle.standardError.write("{\"host\":\"swift-wasmkit\",\"rows\":\(rows),\"traps\":\(traps)}\n".data(using: .utf8)!)

case "startup":
    let wasm = AprvRuntime.bundledWasm()
    let t0 = now()
    let rt = try AprvRuntime(wasm: wasm)
    let t1 = now()
    let v = try AprvInstance(runtime: rt)
    let t2 = now()
    _ = try AprvInstance(runtime: rt)
    let t3 = now()
    let (op, g5) = call(calls, "receipt/verify-genuine-sandbox-g5-against-apple-roots")
    let t4 = now()
    let r = try v.invoke(op, g5); precondition(isVerified(r))
    let t5 = now()
    let r2 = try v.invoke(op, g5); precondition(isVerified(r2))
    let t6 = now()
    let ms = { (a: Double, b: Double) in round1((b - a) * 1000) }
    print("{\"parse_module_ms\":\(ms(t0, t1)),\"first_instance_ms\":\(ms(t1, t2)),\"second_instance_ms\":\(ms(t2, t3)),\"first_call_ms\":\(ms(t4, t5)),\"second_call_ms\":\(ms(t5, t6))}")

case "bench":
    let (op, input) = call(calls, args[3])
    let warm = Int(args[4])!, n = Int(args[5])!
    let v = try AprvInstance()
    for _ in 0..<warm { let r = try v.invoke(op, input); precondition(isVerified(r)) }
    let t = now()
    for _ in 0..<n { let r = try v.invoke(op, input); precondition(isVerified(r)) }
    let us = (now() - t) / Double(n) * 1e6
    print("{\"id\":\(quote(args[3])),\"op\":\(op),\"warm\":\(warm),\"n\":\(n),\"mean_us\":\(Int(us.rounded())),\"per_s\":\(round1(1e6 / us))}")

case "threads":
    let (op, input) = call(calls, args[3])
    let threads = Int(args[4])!, warm = Int(args[5])!, n = Int(args[6])!
    let ready = DispatchGroup(), done = DispatchGroup()
    let start = DispatchSemaphore(value: 0)
    let lock = NSLock()
    var bad = 0
    for _ in 0..<threads {
        ready.enter(); done.enter()
        Thread.detachNewThread {
            let v = try! AprvInstance()
            for _ in 0..<warm { _ = try! v.invoke(op, input) }
            ready.leave()
            start.wait()
            var b = 0
            for _ in 0..<n { let r = try! v.invoke(op, input); if !isVerified(r) { b += 1 } }
            lock.lock(); bad += b; lock.unlock()
            done.leave()
        }
    }
    ready.wait()
    let t0 = now()
    for _ in 0..<threads { start.signal() }
    done.wait()
    let s = now() - t0
    print("{\"id\":\(quote(args[3])),\"op\":\(op),\"threads\":\(threads),\"warm_each\":\(warm),\"n_each\":\(n),\"seconds\":\((s * 100).rounded() / 100),\"total_per_s\":\(round1(Double(threads * n) / s)),\"not_verified\":\(bad)}")

case "isolation":
    let (op, g5) = call(calls, "receipt/verify-genuine-sandbox-g5-against-apple-roots")
    let a = try Verifier(), b = try Verifier()
    let ref = try a.call(op, g5)
    do { _ = try a.call(99, []) } catch {}
    let sameB = try b.call(op, g5) == ref, sameA = try a.call(op, g5) == ref
    print("{\"test\":\"independent instances: a trap in A leaves B untouched; A restarts fresh\",\"b_unchanged\":\(sameB),\"a_after_trap\":\(sameA),\"a_traps\":\(a.traps),\"b_traps\":\(b.traps),\"pass\":\(sameB && sameA && a.traps == 1 && b.traps == 0)}")
    let lock = NSLock()
    var good = [Int](repeating: 0, count: 4), traps = [Int](repeating: 0, count: 4), errors = 0
    let done = DispatchGroup()
    for k in 0..<4 {
        done.enter()
        Thread.detachNewThread {
            let v = try! Verifier()
            var g = 0, e = 0
            for i in 0..<70 {
                if i % 7 == 6 {
                    do { _ = try v.call(99, []); e += 1 } catch {}
                } else if (try? v.call(op, g5)) == ref { g += 1 } else { e += 1 }
            }
            lock.lock(); good[k] = g; traps[k] = v.traps; errors += e; lock.unlock()
            done.leave()
        }
    }
    done.wait()
    print("{\"test\":\"4 threads, one Verifier each, a trap every 7th call\",\"good_calls\":\(good),\"traps\":\(traps),\"errors\":\(errors),\"pass\":\(errors == 0 && good == [60, 60, 60, 60] && traps == [10, 10, 10, 10])}")

case "tests":
    runTests(calls)

default:
    fatalError("unknown mode \(mode)")
}
fflush(stdout)
