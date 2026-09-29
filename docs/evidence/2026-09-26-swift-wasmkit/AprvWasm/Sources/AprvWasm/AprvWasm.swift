// Spike only (2026-09-26). The Swift bridge for aprv.wasm's ABI v1 on
// WasmKit. The call lifecycle is the same as in the other bridges:
//   alloc -> copy input -> aprv_call -> bounds-check ptr/len -> COPY result
//   -> aprv_result_free -> dealloc input -> (caller) decode.
// No guest pointer leaves `call`. A trap throws `AprvWasmError.trap`, and
// `Verifier` discards that instance. One `AprvInstance`/`Verifier` per
// thread; the `AprvRuntime` (Engine + parsed Module) is shared.
//
// WasmKit's `Memory.withUnsafe*BufferPointer` stops the process with a
// precondition failure on an out-of-range access, so every range is
// checked against `byteCount` before it is touched.
import Foundation
import WasmKit

public enum AprvOperation: UInt32, Sendable {
    case verifyReceipt = 1, verifySignedData = 2, endpointProduction = 3, endpointSandbox = 4
}

public enum AprvWasmError: Error, CustomStringConvertible {
    /// The module and this bridge disagree on the ABI version.
    case abiMismatch(module: UInt32, caller: UInt32)
    /// The instance trapped: an internal failure, not a verdict.
    case trap(String)
    /// The module is not the expected one (imports or exports).
    case badModule(String)
    case allocFailed(Int)

    public var description: String {
        switch self {
        case .abiMismatch(let m, let c): return "APRV Wasm ABI mismatch: module=\(m), caller=\(c)"
        case .trap(let s): return "Wasm trap: \(s)"
        case .badModule(let s): return "bad module: \(s)"
        case .allocFailed(let n): return "aprv_alloc(\(n)) failed"
        }
    }
}

public let aprvAbiVersion: UInt32 = 1

/// The Engine and the parsed Module: process-wide, shared by every instance.
public final class AprvRuntime: Sendable {
    public let engine: Engine
    public let module: Module

    public init(wasm: [UInt8]) throws {
        engine = Engine()
        module = try parseWasm(bytes: wasm)
        for i in module.imports {
            guard i.module == "aprv", i.name == "clock_now_ms" || i.name == "random_get" else {
                throw AprvWasmError.badModule("unexpected import \(i.module).\(i.name)")
            }
        }
    }

    /// The bytes of the module bundled with this package.
    public static func bundledWasm() -> [UInt8] {
        guard let url = Bundle.module.url(forResource: "aprv", withExtension: "wasm"),
              let data = try? Data(contentsOf: url) else { fatalError("aprv.wasm missing from the bundle") }
        return [UInt8](data)
    }

    /// The runtime over the bundled module, created on first use.
    public static let shared: AprvRuntime = {
        do { return try AprvRuntime(wasm: bundledWasm()) } catch { fatalError("aprv.wasm: \(error)") }
    }()
}

/// Counts of host-function calls, per instance (for the tests).
public final class ImportCounter {
    public var clock = 0
    public var random = 0
}

/// One Store + Instance. Not thread-safe; never share it between threads.
public final class AprvInstance {
    public let store: Store
    public let instance: Instance
    public let memory: Memory
    public let counter = ImportCounter()
    let alloc, dealloc, call, resultPtr, resultLen, resultFree: Function
    public let moduleVersion: UInt32

    public init(runtime: AprvRuntime = .shared) throws {
        store = Store(engine: runtime.engine)
        let counter = self.counter
        var imports = Imports()
        imports.define(module: "aprv", name: "clock_now_ms", Function(store: store, parameters: [], results: [.f64]) { _, _ in
            counter.clock += 1
            let ms = (Date().timeIntervalSince1970 * 1000).rounded(.down)
            return [.f64(ms.bitPattern)]
        })
        imports.define(module: "aprv", name: "random_get", Function(store: store, parameters: [.i32, .i32], results: [.i32]) { caller, args in
            counter.random += 1
            guard case .i32(let p) = args[0], case .i32(let n) = args[1],
                  let memory = caller.instance?.exports[memory: "memory"],
                  UInt64(p) + UInt64(n) <= UInt64(memory.byteCount) else {
                throw AprvWasmError.trap("aprv.random_get out of bounds")
            }
            if n > 0 {
                memory.withUnsafeMutableBufferPointer(offset: UInt(p), count: Int(n)) { buf in
                    var rng = SystemRandomNumberGenerator()
                    for i in 0..<buf.count { buf[i] = rng.next() }
                }
            }
            return [.i32(0)]
        })
        let inst = try runtime.module.instantiate(store: store, imports: imports)
        instance = inst
        let export = { (name: String) throws -> Function in
            guard let f = inst.exports[function: name] else { throw AprvWasmError.badModule("missing export \(name)") }
            return f
        }
        guard let mem = inst.exports[memory: "memory"] else { throw AprvWasmError.badModule("missing memory") }
        memory = mem
        alloc = try export("aprv_alloc")
        dealloc = try export("aprv_dealloc")
        call = try export("aprv_call")
        resultPtr = try export("aprv_result_ptr")
        resultLen = try export("aprv_result_len")
        resultFree = try export("aprv_result_free")
        _ = try export("_initialize").invoke([])
        let version = try Self.u32(export("aprv_abi_version").invoke([]))
        moduleVersion = version
        guard version == aprvAbiVersion else {
            throw AprvWasmError.abiMismatch(module: version, caller: aprvAbiVersion)
        }
    }

    static func u32(_ v: [Value]) throws -> UInt32 {
        guard v.count == 1, case .i32(let x) = v[0] else { throw AprvWasmError.badModule("unexpected result \(v)") }
        return x
    }

    /// A raw export call, for the ABI tests. Traps come back as `AprvWasmError.trap`.
    public func raw(_ name: String, _ args: [UInt32]) throws -> [Value] {
        guard let f = instance.exports[function: name] else { throw AprvWasmError.badModule("missing export \(name)") }
        do { return try f.invoke(args.map { .i32($0) }) } catch let t as Trap { throw AprvWasmError.trap(t.description) }
    }

    /// The whole lifecycle. `abiVersion` other than 1 only for the ABI tests.
    public func invoke(_ operation: UInt32, _ input: [UInt8], abiVersion: UInt32 = aprvAbiVersion) throws -> [UInt8] {
        let n = input.count
        let p = try Self.u32(alloc.invoke([.i32(UInt32(truncatingIfNeeded: n))]))
        if p == 0 { throw AprvWasmError.allocFailed(n) }
        if n > 0 {
            guard UInt64(p) + UInt64(n) <= UInt64(memory.byteCount) else { throw AprvWasmError.trap("aprv_alloc returned an out-of-range block") }
            memory.withUnsafeMutableBufferPointer(offset: UInt(p), count: n) { dst in
                input.withUnsafeBytes { dst.copyMemory(from: $0) }
            }
        }
        let h: UInt32
        do {
            h = try Self.u32(call.invoke([.i32(abiVersion), .i32(operation), .i32(p), .i32(UInt32(n))]))
        } catch let t as Trap {
            if abiVersion != moduleVersion { throw AprvWasmError.abiMismatch(module: moduleVersion, caller: abiVersion) }
            throw AprvWasmError.trap(t.description)
        }
        do {
            let rp = try Self.u32(resultPtr.invoke([.i32(h)]))
            let rn = try Self.u32(resultLen.invoke([.i32(h)]))
            guard UInt64(rp) + UInt64(rn) <= UInt64(memory.byteCount) else { throw AprvWasmError.trap("result out of bounds") }
            let out = memory.withUnsafeBufferPointer(offset: UInt(rp), count: Int(rn)) { [UInt8]($0) }  // a copy
            _ = try resultFree.invoke([.i32(h)])
            _ = try dealloc.invoke([.i32(p), .i32(UInt32(n))])
            return out
        } catch let t as Trap {
            throw AprvWasmError.trap(t.description)
        }
    }
}

/// A verification result as the module returns it (JSON).
public struct AprvResult: @unchecked Sendable {
    public let json: [String: Any]
    public var verified: Bool { json["verified"] as? Bool ?? false }
    public var reason: String? { json["reason"] as? String }
    public var payload: [String: Any]? { json["payload"] as? [String: Any] }
}

/// The facade: one per worker. A trap discards the instance; the next call
/// starts a fresh one. Verification failures are values.
public final class Verifier {
    let runtime: AprvRuntime
    var current: AprvInstance?
    public private(set) var traps = 0

    public init(runtime: AprvRuntime = .shared) throws {
        self.runtime = runtime
        current = try AprvInstance(runtime: runtime)
    }

    public func call(_ operation: UInt32, _ input: [UInt8], abiVersion: UInt32 = aprvAbiVersion) throws -> [UInt8] {
        let inst = try current ?? AprvInstance(runtime: runtime)
        current = inst
        do {
            return try inst.invoke(operation, input, abiVersion: abiVersion)
        } catch let e as AprvWasmError {
            if case .trap = e { traps += 1 }
            current = nil  // trap or mismatch => discard
            throw e
        }
    }

    func decode(_ bytes: [UInt8]) throws -> AprvResult {
        guard let obj = try JSONSerialization.jsonObject(with: Data(bytes)) as? [String: Any] else {
            throw AprvWasmError.badModule("result is not a JSON object")
        }
        return AprvResult(json: obj)
    }

    /// `receiptData`: the base64 string a client sends.
    public func verifyReceipt(_ receiptData: String) throws -> AprvResult {
        try decode(call(AprvOperation.verifyReceipt.rawValue, Array(receiptData.utf8)))
    }

    public func verifySignedData(_ jws: String) throws -> AprvResult {
        try decode(call(AprvOperation.verifySignedData.rawValue, Array(jws.utf8)))
    }

    /// The verifyReceipt answer, byte for byte, as text.
    public func verifyReceiptEndpoint(production: Bool, body: [UInt8]) throws -> String {
        let op: AprvOperation = production ? .endpointProduction : .endpointSandbox
        return String(decoding: try call(op.rawValue, body), as: UTF8.self)
    }
}
