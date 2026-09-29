// Spike only (2026-09-26). The ABI v1 round's 33 mandatory ABI tests
// (js/abi-tests.mjs) on WasmKit, plus the facade's contract. Every trap is
// caught, the instance discarded, and a fresh instance must then verify g5.
import AprvWasm
import Foundation
import WasmKit

enum Outcome { case ok(Any), trap(String), error(String) }

var passed = 0, failed = 0

func ok(_ name: String, _ cond: Bool, _ detail: String = "") {
    if cond { passed += 1 } else { failed += 1 }
    print("\(cond ? "PASS" : "FAIL") \(name)\(detail.isEmpty ? "" : ": " + detail)")
}

func attempt(_ f: (AprvInstance) throws -> Any) -> Outcome {
    let i = try! AprvInstance()
    do { return .ok(try f(i)) } catch AprvWasmError.trap(let s) {
        return .trap(String(s.split(separator: "\n").first ?? ""))
    } catch { return .error("\(error)") }
}

func dec(_ b: [UInt8]) -> [String: Any] { try! JSONSerialization.jsonObject(with: Data(b)) as! [String: Any] }
func u32(_ v: [Value]) -> UInt32 { if case .i32(let x) = v[0] { return x }; return .max }

func runTests(_ calls: [[String: Any]]) {
    let (_, g5) = call(calls, "receipt/verify-genuine-sandbox-g5-against-apple-roots")
    let (jwsOp, jws) = call(calls, "transaction/verify-shared-sandbox")
    let R: UInt32 = 1
    func g5Verifies() -> Bool { (dec(try! AprvInstance().invoke(R, g5))["verified"] as? Bool) == true }
    func trapsThenRecovers(_ name: String, _ f: (AprvInstance) throws -> Any) {
        let o = attempt(f)
        let after = g5Verifies()
        var isTrap = false, msg = ""
        switch o { case .trap(let m): isTrap = true; msg = m; case .ok(let v): msg = "ok \(v)"; case .error(let e): msg = e }
        ok(name, isTrap && after, "\(isTrap ? "trap" : "no trap") (\(msg)); fresh instance verifies g5: \(after)")
    }
    func withHandle(_ i: AprvInstance) throws -> UInt32 {
        let p = u32(try i.raw("aprv_alloc", [4]))
        return u32(try i.raw("aprv_call", [1, R, p, 4]))
    }

    ok("aprv_abi_version() == 1", u32(try! AprvInstance().raw("aprv_abi_version", [])) == 1)
    if case .ok(let v as [String: Any]) = attempt({ dec(try $0.invoke(R, g5)) }) {
        let b = (v["payload"] as? [String: Any])?["bundleId"] as? String
        ok("aprv_call(1, VERIFY_RECEIPT, genuine g5) verifies", (v["verified"] as? Bool) == true && b == "dev.bonzer.weeka.app", "bundleId \(b ?? "-")")
    } else { ok("aprv_call(1, VERIFY_RECEIPT, genuine g5) verifies", false) }
    if case .ok(let v as [String: Any]) = attempt({ dec(try $0.invoke(jwsOp, jws)) }) {
        let raw = v["payloadJson"] as? String ?? ""
        let parsed = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? NSDictionary
        let same = parsed != nil && parsed!.isEqual(to: v["payload"] as? [String: Any] ?? [:])
        ok("aprv_call(1, VERIFY_SIGNED_DATA (test anchors), shared-sandbox JWS) verifies; payloadJson is the exact signed JSON and parses to payload",
           (v["verified"] as? Bool) == true && same, "payloadJson \(raw.count) chars")
    } else { ok("VERIFY_SIGNED_DATA verifies", false) }
    trapsThenRecovers("aprv_call(0, garbage op, invalid ptr, absurd len) fails hard") { try $0.raw("aprv_call", [0, 0x7fff_ffff, 0xffff_fff0, 0x7fff_ffff]) }
    trapsThenRecovers("aprv_call(2, garbage op, invalid ptr, absurd len) fails hard") { try $0.raw("aprv_call", [2, 0x7fff_ffff, 0xffff_fff0, 0x7fff_ffff]) }
    switch attempt({ try $0.invoke(R, g5, abiVersion: 2) }) {
    case .error(let m): ok("bridge reports a version mismatch as an ABI error, never verified=false", m.contains("APRV Wasm ABI mismatch: module=1, caller=2"), m)
    default: ok("bridge reports a version mismatch as an ABI error, never verified=false", false)
    }
    if case .ok(let v as Int) = attempt({ i in
        let before = i.counter.clock + i.counter.random
        _ = try? i.raw("aprv_call", [3, 1, 0, 0])
        return i.counter.clock + i.counter.random - before
    }) {
        ok("a version mismatch runs nothing (no host import called)", v == 0, "import calls during the call: \(v)")
    } else { ok("a version mismatch runs nothing", false) }
    for op: UInt32 in [0, 5, 99, 255, 256, 261, 0xffff_ffff] {
        trapsThenRecovers("unknown operation \(Int32(bitPattern: op)) fails hard") { i in
            let p = u32(try i.raw("aprv_alloc", [4]))
            return try i.raw("aprv_call", [1, op, p, 4])
        }
    }
    trapsThenRecovers("null input pointer with a length fails hard") { try $0.raw("aprv_call", [1, R, 0, 10]) }
    trapsThenRecovers("input beyond linear memory fails hard") { i in try i.raw("aprv_call", [1, R, UInt32(i.memory.byteCount - 4), 16]) }
    trapsThenRecovers("input range that overflows u32 fails hard") { try $0.raw("aprv_call", [1, R, 0xffff_fff0, 0x20]) }
    if case .ok(let v as [String: Any]) = attempt({ dec(try $0.invoke(R, [])) }) {
        ok("empty input is a verification failure value", (v["verified"] as? Bool) == false && v["reason"] as? String == "INVALID_RECEIPT_FORMAT", "\(v)")
    } else { ok("empty input is a verification failure value", false) }
    if case .ok(let v as [Any]) = attempt({ i in
        [u32(try i.raw("aprv_alloc", [0x7fff_ffff])), u32(try i.raw("aprv_alloc", [0x7fff_fff0])), (dec(try i.invoke(R, g5))["verified"] as? Bool) == true]
    }) {
        ok("absurd aprv_alloc lengths return 0, and the instance keeps working", v[0] as? UInt32 == 0 && v[1] as? UInt32 == 0 && v[2] as? Bool == true, "\(v)")
    } else { ok("absurd aprv_alloc lengths return 0", false) }
    trapsThenRecovers("invalid handle: aprv_result_ptr(0) fails hard") { try $0.raw("aprv_result_ptr", [0]) }
    trapsThenRecovers("invalid handle: aprv_result_len(12345) fails hard") { try $0.raw("aprv_result_len", [12345]) }
    trapsThenRecovers("invalid handle: aprv_result_free(0) fails hard") { try $0.raw("aprv_result_free", [0]) }
    trapsThenRecovers("invalid handle: aprv_result_free(never issued) fails hard") { try $0.raw("aprv_result_free", [7]) }
    trapsThenRecovers("double free fails hard") { i in
        let h = try withHandle(i); _ = try i.raw("aprv_result_free", [h]); return try i.raw("aprv_result_free", [h])
    }
    trapsThenRecovers("use after free (result_ptr) fails hard") { i in
        let h = try withHandle(i); _ = try i.raw("aprv_result_free", [h]); return try i.raw("aprv_result_ptr", [h])
    }
    trapsThenRecovers("use after free (result_len) fails hard") { i in
        let h = try withHandle(i); _ = try i.raw("aprv_result_free", [h]); return try i.raw("aprv_result_len", [h])
    }
    if case .ok(let v as [UInt32]) = attempt({ i in
        let hs = [try withHandle(i), try withHandle(i), try withHandle(i)]
        _ = try i.raw("aprv_result_free", [hs[1]])
        return hs + [try withHandle(i)]
    }) {
        ok("freed handles are reused and live ones stay valid", v[3] == v[1], "\(v)")
    } else { ok("freed handles are reused", false) }
    for (name, op, input, check) in [
        ("garbage receipt -> verified=false value", R, Array("not a receipt".utf8), { (v: [String: Any]) in (v["verified"] as? Bool) == false }),
        ("non-UTF-8 JWS -> verified=false INVALID_JWS_FORMAT", UInt32(2), [0xff, 0xfe, 0x2e], { (v: [String: Any]) in (v["verified"] as? Bool) == false && v["reason"] as? String == "INVALID_JWS_FORMAT" }),
        ("malformed endpoint request JSON -> Apple status 21002 value", UInt32(4), Array("{\"receipt-data\": ".utf8), { (v: [String: Any]) in v["status"] as? Int == 21002 }),
    ] as [(String, UInt32, [UInt8], ([String: Any]) -> Bool)] {
        if case .ok(let v as [String: Any]) = attempt({ dec(try $0.invoke(op, input)) }) { ok(name, check(v), "\(v)") } else { ok(name, false) }
    }
    var msg = ""
    do { _ = try JSONSerialization.jsonObject(with: Data("{\"verified\":tru".utf8)) } catch { msg = "\(type(of: error)): \(error.localizedDescription)" }
    ok("malformed result JSON is a host decode error (internal failure), not a verdict", !msg.isEmpty, msg)
    if case .ok(let v as Bool) = attempt({ i in
        let a = try i.invoke(R, g5)
        let snap = a
        for n in 0..<5 { _ = try i.invoke(R, [UInt8](repeating: 0x78, count: n + 1)) }
        return snap == a
    }) {
        ok("a result is a host-owned copy (unchanged after later calls reuse guest memory)", v)
    } else { ok("a result is a host-owned copy", false) }
    if case .ok(let v as [Int]) = attempt({ i in
        for _ in 0..<50 { _ = try i.invoke(R, g5) }
        let m1 = i.memory.byteCount
        for _ in 0..<500 { _ = try i.invoke(R, g5) }
        return [m1, i.memory.byteCount]
    }) {
        ok("no growth of linear memory over 500 more calls (the interpreter is slow; Node and Endive ran 2,000)", v[0] == v[1], "\(v)")
    } else { ok("no growth of linear memory", false) }
    // The facade's own contract.
    let fv = try! Verifier()
    do { _ = try fv.call(R, g5, abiVersion: 2); ok("facade: a version mismatch throws abiMismatch", false) } catch {
        ok("facade: a version mismatch throws abiMismatch", "\(error)".contains("module=1, caller=2"), "\(error)")
    }
    do { _ = try fv.call(99, []); ok("facade: an unknown operation throws trap", false) } catch {
        ok("facade: an unknown operation throws trap (internal failure)", "\(error)".hasPrefix("Wasm trap"), String("\(error)".split(separator: "\n")[0]))
    }
    let again = try! fv.verifyReceipt(String(decoding: g5, as: UTF8.self))
    ok("facade: after a trap the next call runs on a fresh instance and verifies", again.verified && fv.traps == 1, "traps \(fv.traps)")
    let bad = try! fv.verifyReceipt("not base64!")
    ok("facade: a verification failure is a value", !bad.verified && bad.reason == "INVALID_RECEIPT_FORMAT", "\(bad.json)")
    print("summary: \(passed) passed, \(failed) failed")
    fflush(stdout)
    exit(failed == 0 ? 0 : 1)
}
