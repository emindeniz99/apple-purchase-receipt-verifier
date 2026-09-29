// Spike only (2026-09-29, round 13). The WasmKit host's harness.
//   aprv-cabi calls MODULE CALLS.jsonl          rows in the Node runner's format (stdout)
//   aprv-cabi tests MODULE CASES.jsonl          the ABI tests (Tests.swift)
//   aprv-cabi startup v1|cabi MODULE CASES.jsonl   one start-up to the first g5 result
import Foundation
import WasmKit

func nowMs() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }

func rows(_ path: String) throws -> [[String: Any]] {
    let text = try String(contentsOfFile: path, encoding: .utf8)
    return try text.split(separator: "\n").map { try JSONSerialization.jsonObject(with: Data($0.utf8)) as! [String: Any] }
}

func bytes(_ r: [String: Any]) -> [UInt8] { [UInt8](Data(base64Encoded: r["b64"] as! String)!) }

func jsonString(_ s: String) -> String {
    let d = try! JSONSerialization.data(withJSONObject: [s], options: [.withoutEscapingSlashes])
    return String(decoding: d.dropFirst().dropLast(), as: UTF8.self)
}

func load(_ path: String) throws -> (Engine, Module) {
    let wasm = [UInt8](try Data(contentsOf: URL(fileURLWithPath: path)))
    return (Engine(), try parseWasm(bytes: wasm))
}

func runCalls(_ modPath: String, _ callsPath: String) throws {
    let (engine, module) = try load(modPath)
    var inst: [String: Cabi] = [:]
    var n = 0, traps = 0
    var out = ""
    for r in try rows(callsPath) {
        n += 1
        let id = jsonString(r["id"] as! String)
        if let m = r["map"] as? String { out += "{\"id\":\(id),\"map\":\(jsonString(m))}\n"; continue }
        let config = r["config"] as! String
        var answer: String? = nil
        var g = inst[config]
        if g == nil {
            let fresh = try Cabi(engine: engine, module: module)
            let ok = try fresh.call("init", Array(config.utf8))
            if ok == "{\"ok\":true}" { inst[config] = fresh } else { answer = ok }  // init refused the config
            g = fresh
        }
        let now = (r["now"] as? NSNumber).map { UInt64(truncatingIfNeeded: $0.int64Value) } ?? nowMs()
        do {
            if answer == nil {
                switch r["fn"] as! String {
                case "verify-receipt": answer = try g!.call("verify-receipt", now, bytes(r))
                case "verify-signed-data": answer = try g!.call("verify-signed-data", now, bytes(r))
                default: answer = try g!.call("verify-receipt-endpoint", UInt32((r["env"] as! NSNumber).uint32Value), now, bytes(r))
                }
            }
            out += "{\"id\":\(id),\"out\":\(jsonString(answer!))}\n"
        } catch CabiError.trap(let t) {
            traps += 1
            inst[config] = nil
            out += "{\"id\":\(id),\"trap\":\(jsonString(t))}\n"
        }
    }
    FileHandle.standardOutput.write(Data(out.utf8))
    FileHandle.standardError.write(Data("{\"host\":\"wasmkit 0.4.0\",\"rows\":\(n),\"traps\":\(traps)}\n".utf8))
}

let args = CommandLine.arguments
switch args.count > 1 ? args[1] : "" {
case "calls": try runCalls(args[2], args[3])
case "tests": exit(Int32(try runTests(args[2], args[3])))
case "startup": try startup(args[2], args[3], args[4])
default:
    FileHandle.standardError.write(Data("usage: aprv-cabi calls|tests MODULE FILE.jsonl | startup v1|cabi MODULE CASES.jsonl\n".utf8))
    exit(2)
}
