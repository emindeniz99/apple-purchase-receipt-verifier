// Spike only (2026-09-29, round 13). Start-up of one process on WasmKit to
// the first g5 result: the ABI v1 module through ABI v1's call lifecycle
// (as round 7's AprvWasm.swift), or the canonical-ABI module through Cabi.
// Prints parse, instantiate(+init), first and second call, and the process
// uptime at the first result (from /proc/self/stat's start time).
import Foundation
import WasmKit

func v1Instance(_ engine: Engine, _ module: Module) throws -> Instance {
    let store = Store(engine: engine)
    var imports = Imports()
    imports.define(module: "aprv", name: "clock_now_ms", Function(store: store, parameters: [], results: [.f64]) { _, _ in
        [.f64((Date().timeIntervalSince1970 * 1000).rounded(.down).bitPattern)]
    })
    imports.define(module: "aprv", name: "random_get", Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
        guard case .i32(let p) = args[0], case .i32(let n) = args[1], let m = caller.instance?.exports[memory: "memory"] else { return [.i32(1)] }
        var rng = SystemRandomNumberGenerator()
        try Cabi.write(m, p, (0..<n).map { _ in rng.next() })
        return [.i32(0)]
    })
    let inst = try module.instantiate(store: store, imports: imports)
    _ = try inst.exports[function: "_initialize"]!.invoke([])
    return inst
}

func v1Call(_ inst: Instance, _ op: UInt32, _ input: [UInt8]) throws -> String {
    let f = { (n: String, a: [UInt32]) throws -> UInt32 in
        let r = try inst.exports[function: n]!.invoke(a.map { .i32($0) })
        return r.isEmpty ? 0 : try Cabi.u32(r)
    }
    let m = inst.exports[memory: "memory"]!
    let p = try f("aprv_alloc", [UInt32(input.count)])
    try Cabi.write(m, p, input)
    let h = try f("aprv_call", [1, op, p, UInt32(input.count)])
    let out = try Cabi.read(m, try f("aprv_result_ptr", [h]), try f("aprv_result_len", [h]))
    _ = try f("aprv_result_free", [h])
    _ = try f("aprv_dealloc", [p, UInt32(input.count)])
    return String(decoding: out, as: UTF8.self)
}

func uptimeMs() -> Double {
    let stat = (try? String(contentsOfFile: "/proc/self/stat", encoding: .utf8)) ?? ""
    let fields = stat.split(separator: ")").last?.split(separator: " ") ?? []
    let ticks = fields.count > 19 ? Double(fields[19]) ?? 0 : 0   // field 22: starttime, in clock ticks since boot
    let boot = Double((try? String(contentsOfFile: "/proc/uptime", encoding: .utf8))?.split(separator: " ").first ?? "0") ?? 0
    return (boot - ticks / 100) * 1000
}

func startup(_ which: String, _ modPath: String, _ casesPath: String) throws {
    let g5row = try String(contentsOfFile: casesPath, encoding: .utf8).split(separator: "\n")
        .first { $0.contains("\"receipt/verify-genuine-sandbox-g5-against-apple-roots\"") }!
    let g5 = bytes(try JSONSerialization.jsonObject(with: Data(g5row.utf8)) as! [String: Any])
    let t0 = Date()
    let (engine, module) = try load(modPath)
    let t1 = Date()
    var first = "", second = "", atFirst = 0.0
    var t2 = Date(), t3 = Date()
    if which == "v1" {
        let inst = try v1Instance(engine, module)
        t2 = Date()
        first = try v1Call(inst, 1, g5)
        atFirst = uptimeMs(); t3 = Date()
        second = try v1Call(inst, 1, g5)
    } else {
        let g = try Cabi(engine: engine, module: module)
        _ = try g.call("init", [UInt8]())
        t2 = Date()
        first = try g.call("verify-receipt", nowMs(), g5)
        atFirst = uptimeMs(); t3 = Date()
        second = try g.call("verify-receipt", nowMs(), g5)
    }
    let t4 = Date()
    guard first.contains("\"verified\":true"), second.contains("\"verified\":true") else { fatalError(first) }
    let ms = { (a: Date, b: Date) in String(format: "%.1f", b.timeIntervalSince(a) * 1000) }
    print("{\"module\":\"\(which == "v1" ? "ABI v1" : "canonical ABI")\",\"parse_ms\":\(ms(t0, t1)),\"instantiate_and_init_ms\":\(ms(t1, t2)),\"first_g5_ms\":\(ms(t2, t3)),\"second_g5_ms\":\(ms(t3, t4)),\"uptime_at_first_result_ms\":\(String(format: "%.0f", atFirst))}")
}
