// Spike only (2026-09-29, round 13). The round-13 ABI tests on WasmKit, on
// the core exports called by hand (the cases of hosts/wazero/tests.go).
// "RECORD" lines report behaviour with no pass/fail expectation.
import Foundation
import WasmKit

var failed = 0

func check(_ name: String, _ ok: Bool, _ detail: String) {
    if !ok { failed += 1 }
    print("\(ok ? "PASS" : "FAIL") \(name): \(detail.prefix(220))")
}

func record(_ name: String, _ detail: String) { print("RECORD \(name): \(detail.prefix(260))") }

func attempt(_ f: () throws -> String) -> String {
    do { return try f() } catch { return "TRAP/ERROR \(error)".components(separatedBy: "\n")[0] }
}

func raw(_ g: Cabi, _ name: String, _ args: [Value]) -> String {
    do { return "results \(try g.instance.exports[function: name]!.invoke(args))" } catch { return "TRAP/ERROR \(error)".components(separatedBy: "\n")[0] }
}

func runTests(_ modPath: String, _ casesPath: String) throws -> Int {
    let (engine, module) = try load(modPath)
    let all = try rows(casesPath)
    let g5 = bytes(all.first { $0["id"] as? String == "receipt/verify-genuine-sandbox-g5-against-apple-roots" }!)
    let jr = all.first { $0["id"] as? String == "transaction/verify-shared-sandbox" }!
    let jws = bytes(jr), jwsConfig = Array((jr["config"] as! String).utf8)
    let req = Array("{\"receipt-data\":\"".utf8) + g5 + Array("\"}".utf8)
    let none: [UInt8] = []
    func fresh(_ c: [UInt8]) throws -> Cabi { let g = try Cabi(engine: engine, module: module); _ = try g.call("init", c); return g }
    func g5ok(_ g: Cabi) -> Bool { attempt { try g.call("verify-receipt", nowMs(), g5) }.contains("\"verified\":true") }
    let trapped = { (s: String) in s.hasPrefix("TRAP/ERROR trap") }

    check("init(empty) answers {\"ok\":true}", attempt { try Cabi(engine: engine, module: module).call("init", none) } == "{\"ok\":true}", "")
    let g0 = try Cabi(engine: engine, module: module)
    var s = attempt { try g0.call("verify-receipt", nowMs(), g5) }
    check("verify before init traps", trapped(s), s)
    let g1 = try fresh(none)
    s = attempt { try g1.call("init", none) }
    check("a second init traps", trapped(s), s)
    let g2 = try Cabi(engine: engine, module: module)
    s = attempt { try g2.call("init", Array("{not json".utf8)) }
    check("a config that is not JSON is {\"ok\":false}, and init can be retried", s.contains("\"ok\":false") && attempt { try g2.call("init", none) } == "{\"ok\":true}", s)
    let g = try fresh(none)
    s = attempt { try g.call("verify-receipt", nowMs(), g5) }
    check("verify-receipt(genuine g5) verifies", s.contains("\"verified\":true"), s)
    let gj = try fresh(jwsConfig)
    s = attempt { try gj.call("verify-signed-data", nowMs(), jws) }
    check("verify-signed-data(shared-sandbox JWS, its test roots) verifies", s.contains("\"verified\":true"), s)
    s = attempt { try g.call("verify-receipt-endpoint", UInt32(1), nowMs(), req) }
    check("verify-receipt-endpoint(env 1 = sandbox, g5) answers status 0", s.contains("\"status\":0"), s)
    s = attempt { try g.call("verify-signed-data", nowMs(), [0x65, 0x79, 0xff, 0xfe, 0x2e, 0x78] as [UInt8]) }
    check("a JWS that is not UTF-8 reaches the guest and is a value (ABI v1's answer)", s.contains("jws is not valid UTF-8"), s)
    s = attempt { try g.call("verify-receipt", UInt32(5), g5) }
    check("the lowering helper refuses a UInt32 where the WIT says u64 (loud host error, no call)", s.contains("the WIT type is d"), s)
    s = attempt { try g.call("verify-receipt-endpoint", UInt64(1), nowMs(), req) }
    check("the lowering helper refuses a UInt64 where the WIT says u32", s.contains("the WIT type is w"), s)
    s = attempt { try g.call("verify-receipt", nowMs(), 42) }
    check("the lowering helper refuses an Int where the WIT says list<u8>", s.contains("the WIT type is b"), s)
    s = attempt { try g.call("verify-receipt", nowMs()) }
    check("the lowering helper refuses a wrong argument count", s.contains("wrong argument count"), s)
    check("  ... and the instance still verifies g5", g5ok(g), "")

    for env: UInt32 in [2, 255, 0xFFFF_FFFF] {
        let ge = try fresh(none)
        s = attempt { try ge.call("verify-receipt-endpoint", env, nowMs(), req) }
        check("endpoint with env \(env) traps", trapped(s), s)
    }

    let iface = "aprv:verifier/verify@1.0.0#"
    let gp = try fresh(none)
    let a = try gp.lower("init", [g5])
    let rpv = try gp.instance.exports[function: iface + "verify-receipt"]!.invoke([.i64(nowMs())] + a)
    record("double post-return on one result", "first: " + raw(gp, "cabi_post_" + iface + "verify-receipt", rpv) + "; second: "
           + raw(gp, "cabi_post_" + iface + "verify-receipt", rpv) + "; the instance verifies g5 afterwards: \(g5ok(gp))")
    let gf = try fresh(none)
    let foreign = try gf.lower("init", [Array("12345678".utf8)])[0]
    record("post-return with a foreign pointer (a heap block no export returned)",
           raw(gf, "cabi_post_" + iface + "verify-receipt", [foreign]) + "; the instance verifies g5 afterwards: \(g5ok(gf))")

    randomTrim = 1
    let gr = try fresh(jwsConfig)
    s = attempt { try gr.call("verify-signed-data", nowMs(), jws) }
    randomTrim = 0
    check("random-get answering the wrong length traps", trapped(s), s)

    let ia = try fresh(none), ib = try fresh(none)
    let before = g5ok(ib)
    s = attempt { try ia.call("verify-receipt-endpoint", UInt32(2), nowMs(), req) }
    check("isolation: a trap (env 2) in one instance leaves another verifying", trapped(s) && before && g5ok(ib) && g5ok(ib), s)
    record("the trapped instance itself, called again (a host should discard it)", attempt { try ia.call("verify-receipt", nowMs(), g5) })
    print("summary: \(failed) failed")
    return failed
}
