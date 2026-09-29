// Spike only (2026-09-29, round 13). The canonical-ABI aprv module on
// WasmKit, called by hand. The lines between the "canonical ABI" markers
// are all a host needs: one generic lowering helper for the four calls and
// the one import (scripts/count.sh counts them). WasmKit stops the process
// on an out-of-range memory access, so every range is checked first.
import WasmKit

var randomTrim: UInt32 = 0 // test hook (Tests.swift): shorten random-get's answer

// --- canonical ABI (hand-written) begin ---
enum CabiError: Error { case trap(String), usage(String) }

final class Cabi {
    static let iface = "aprv:verifier/verify@1.0.0#"
    /// Each export's WIT parameters, in order: "w" u32, "d" u64, "b" list<u8>.
    static let sigs: [String: [Character]] = ["init": ["b"], "verify-receipt": ["d", "b"],
                                              "verify-signed-data": ["d", "b"], "verify-receipt-endpoint": ["w", "d", "b"]]
    let instance: Instance
    let memory: Memory
    let realloc: Function

    init(engine: Engine, module: Module) throws {
        let store = Store(engine: engine)
        var imports = Imports()
        // random-get: func(len: u32) -> list<u8>, lowered (len, retptr); the list is
        // allocated in guest memory with the guest's cabi_realloc.
        imports.define(module: "aprv:verifier/host@1.0.0", name: "random-get",
                       Function(store: store, parameters: [.i32, .i32], results: []) { caller, args in
            guard case .i32(let n0) = args[0], case .i32(let retptr) = args[1], let inst = caller.instance,
                  let mem = inst.exports[memory: "memory"], let re = inst.exports[function: "cabi_realloc"] else {
                throw CabiError.trap("random-get: unexpected call")
            }
            let n = n0 - randomTrim // test hook
            let p = try Cabi.u32(re.invoke([.i32(0), .i32(0), .i32(1), .i32(n)]))
            var rng = SystemRandomNumberGenerator()
            try Cabi.write(mem, p, (0..<n).map { _ in rng.next() })
            try Cabi.write(mem, retptr, Cabi.le(p) + Cabi.le(n))
            return []
        })
        instance = try module.instantiate(store: store, imports: imports)
        guard let m = instance.exports[memory: "memory"], let r = instance.exports[function: "cabi_realloc"] else {
            throw CabiError.usage("not the canonical-ABI aprv module")
        }
        memory = m
        realloc = r
    }

    static func le(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }

    static func u32(_ v: [Value]) throws -> UInt32 {
        guard v.count == 1, case .i32(let x) = v[0] else { throw CabiError.trap("unexpected result \(v)") }
        return x
    }

    static func write(_ m: Memory, _ p: UInt32, _ b: [UInt8]) throws {
        guard UInt64(p) + UInt64(b.count) <= UInt64(m.byteCount) else { throw CabiError.trap("write out of range") }
        if !b.isEmpty { m.withUnsafeMutableBufferPointer(offset: UInt(p), count: b.count) { d in b.withUnsafeBytes { d.copyMemory(from: $0) } } }
    }

    static func read(_ m: Memory, _ p: UInt32, _ n: UInt32) throws -> [UInt8] {
        guard UInt64(p) + UInt64(n) <= UInt64(m.byteCount) else { throw CabiError.trap("read out of range") }
        return n == 0 ? [] : m.withUnsafeBufferPointer(offset: UInt(p), count: Int(n)) { [UInt8]($0) }
    }

    /// Lowers WIT values to core arguments, checked against fn's signature: a
    /// UInt32 is a u32 and a UInt64 a u64 (scalars); [UInt8] or String is a
    /// list<u8>, copied into a guest buffer from cabi_realloc (the guest takes
    /// ownership) and passed as (ptr, len). A wrong count or type is an error.
    func lower(_ fn: String, _ args: [Any]) throws -> [Value] {
        guard let sig = Cabi.sigs[fn], sig.count == args.count else { throw CabiError.usage("\(fn): unknown export or wrong argument count") }
        var out: [Value] = []
        for (i, a) in args.enumerated() {
            let wrong = CabiError.usage("\(fn): argument \(i) is \(type(of: a)), the WIT type is \(sig[i])")
            switch sig[i] {
            case "w":
                guard let v = a as? UInt32 else { throw wrong }
                out.append(.i32(v))
            case "d":
                guard let v = a as? UInt64 else { throw wrong }
                out.append(.i64(v))
            default:
                guard let b = (a as? [UInt8]) ?? (a as? String).map({ Array($0.utf8) }) else { throw wrong }
                let p = try Cabi.u32(realloc.invoke([.i32(0), .i32(0), .i32(1), .i32(UInt32(b.count))]))
                try Cabi.write(memory, p, b)
                out += [.i32(p), .i32(UInt32(b.count))]
            }
        }
        return out
    }

    /// An export whose result is a string: lower, call, lift (copy), post-return.
    func call(_ fn: String, _ args: Any...) throws -> String {
        guard let f = instance.exports[function: Cabi.iface + fn],
              let post = instance.exports[function: "cabi_post_" + Cabi.iface + fn] else { throw CabiError.usage("no export \(fn)") }
        do {
            let rp = try Cabi.u32(f.invoke(lower(fn, args)))
            let ptrLen = try Cabi.read(memory, rp, 8)
            let word = { (o: Int) in (0..<4).reduce(UInt32(0)) { $0 | UInt32(ptrLen[o + $1]) << (8 * $1) } }
            let out = try Cabi.read(memory, word(0), word(4))
            try post.invoke([.i32(rp)])
            return String(decoding: out, as: UTF8.self)
        } catch let t as Trap {
            throw CabiError.trap(t.description)
        }
    }
}
// --- canonical ABI (hand-written) end ---
