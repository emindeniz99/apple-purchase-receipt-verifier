import WasmKit

/// Why the host layer could not produce an answer. None of these is a
/// verdict: the ``Verifier`` reports each as ``Reason/internalError``, with
/// this value as the ``Failure/cause`` so the category is kept.
enum HostError: Error, Sendable, CustomStringConvertible {
    /// The guest trapped, or the runtime refused the call. The instance is
    /// discarded.
    case trap(export: String, detail: String)
    /// The guest answered, but outside its memory, or not UTF-8, or not in
    /// the wire's shape. The instance is discarded.
    case unusableAnswer(export: String, detail: String)
    /// init answered {"ok":false}: the module refused the configuration.
    case initRefused(message: String)
    /// The module is not the aprv:verifier@0.1.0 module this package binds.
    case abiMismatch(String)
    /// The bundled module could not be read, did not match its hash, or did
    /// not parse.
    case moduleUnavailable(String)

    var description: String {
        switch self {
        case .trap(let export, let detail): "aprv.wasm trapped in \(export): \(detail)"
        case .unusableAnswer(let export, let detail): "aprv.wasm's answer to \(export) was unusable: \(detail)"
        case .initRefused(let message): "aprv.wasm refused the configuration: \(message)"
        case .abiMismatch(let detail): "ABI mismatch: \(detail)"
        case .moduleUnavailable(let detail): "aprv.wasm is unavailable: \(detail)"
        }
    }
}

/// The ABI this package binds (docs/rust-core/ARCHITECTURE.md §4). The
/// version in the names is the ABI version: a module of another version has
/// none of these exports and is refused when it loads.
enum Abi {
    static let verify = "aprv:verifier/verify@0.1.0#"
    static let host = "aprv:verifier/host@0.1.0"
    /// Each export's core parameters before the (ptr, len) of its list<u8>:
    /// `env: u32` and `now-ms: u64` flatten to i32 and i64.
    static let exports: [String: [ValueType]] = [
        "init": [], "verify-receipt": [.i64], "verify-signed-data": [.i64], "verify-receipt-endpoint": [.i32, .i64],
    ]
    /// The most random-get may ask for at once. OpenSSL asks for a few dozen
    /// bytes; a module asking for more is not the module we built.
    static let maxRandomRequest: UInt32 = 1 << 20
    /// The most of a verify input copied into linear memory: one byte over
    /// the core's largest cap (3,145,728, the receipt and the endpoint
    /// body). A longer input is cut here, so the core still sees it over its
    /// cap and answers TOO_LARGE (21002 at the endpoint) itself, while the
    /// guest never grows to hold an input of any size a caller hands in.
    static let maxInputBytes = 3_145_729

    /// `input`, cut to ``maxInputBytes``.
    static func capped<C: Collection<UInt8>>(_ input: C) -> [UInt8] { Array(input.prefix(maxInputBytes)) }

    /// `input`, cut to ``maxInputBytes``, without a copy when it fits.
    static func capped(_ input: [UInt8]) -> [UInt8] {
        input.count <= maxInputBytes ? input : Array(input.prefix(maxInputBytes))
    }
}

/// One instance of aprv.wasm in a store of its own, called through the
/// canonical ABI by hand (WasmKit has no component runtime this package
/// uses).
///
/// It serves one call at a time: the return area is one static slot in
/// guest memory, and WasmKit's stores are single-threaded. The ``Pool``
/// guarantees that. Once a call fails inside the guest the instance is dead
/// and answers nothing more, because WasmKit lets a trapped instance keep
/// running and this package must not.
///
/// WasmKit stops the whole process with a precondition failure when the
/// host touches memory outside the guest's bounds, so every range is checked
/// against `byteCount` before memory is touched, and no guest pointer ever
/// leaves this class.
final class Guest: @unchecked Sendable {
    private let instance: Instance
    private let memory: Memory
    private let realloc: Function
    private(set) var dead = false

    /// A fresh instance, before init. `random` supplies random-get's bytes.
    init(_ module: AprvModule, random: @escaping @Sendable (Int) -> [UInt8] = Guest.systemRandomBytes) throws(HostError) {
        let store = Store(engine: module.engine)
        var imports = Imports()
        // random-get: func(len: u32) -> list<u8>, lowered as (len, retptr): the
        // list lives in guest memory from the guest's own cabi_realloc.
        imports.define(
            module: Abi.host, name: "random-get",
            Function(store: store, parameters: [.i32, .i32], results: []) { caller, args in
                guard args.count == 2, case .i32(let n) = args[0], case .i32(let retptr) = args[1],
                    let instance = caller.instance, let memory = instance.exports[memory: "memory"],
                    let realloc = instance.exports[function: "cabi_realloc"]
                else { throw HostError.trap(export: "random-get", detail: "unexpected call") }
                guard n <= Abi.maxRandomRequest else {
                    throw HostError.trap(export: "random-get", detail: "asked for \(n) bytes")
                }
                let bytes = random(Int(n))
                let p = try Guest.pointer(realloc.invoke([.i32(0), .i32(0), .i32(1), .i32(UInt32(bytes.count))]))
                try Guest.write(memory, p, bytes)
                try Guest.write(memory, retptr, Guest.le(p) + Guest.le(UInt32(bytes.count)))
                return []
            })
        do {
            instance = try module.module.instantiate(store: store, imports: imports)
        } catch {
            throw .abiMismatch("instantiating aprv.wasm failed: \(error)")
        }
        guard let memory = instance.exports[memory: "memory"], let realloc = instance.exports[function: "cabi_realloc"]
        else { throw .abiMismatch("aprv.wasm exports no memory or no cabi_realloc") }
        self.memory = memory
        self.realloc = realloc
        // A WASI reactor's _initialize runs its static constructors once,
        // before any export is called (the trap host does the same). The
        // module need not have one; AprvModule checks its signature.
        if let initialize = instance.exports[function: "_initialize"] {
            do {
                _ = try initialize.invoke([])
            } catch {
                throw .trap(export: "_initialize", detail: String(describing: error))
            }
        }
    }

    /// The instance's linear memory, in bytes.
    var memoryBytes: Int { memory.byteCount }

    /// init(config-json) -> string.
    func initialize(_ config: [UInt8]) throws(HostError) -> String {
        try call("init", [], config)
    }

    func verifyReceipt(now: UInt64, _ receiptBase64: [UInt8]) throws(HostError) -> String {
        try call("verify-receipt", [.i64(now)], Abi.capped(receiptBase64))
    }

    func verifySignedData(now: UInt64, _ jws: [UInt8]) throws(HostError) -> String {
        try call("verify-signed-data", [.i64(now)], Abi.capped(jws))
    }

    /// `env` is 0 (production) or 1 (sandbox); the guest traps on anything
    /// else, and ``Verifier`` only ever passes those two.
    func verifyReceiptEndpoint(env: UInt32, now: UInt64, _ requestJson: [UInt8]) throws(HostError) -> String {
        try call("verify-receipt-endpoint", [.i32(env), .i64(now)], Abi.capped(requestJson))
    }

    // --- canonical ABI (hand-written) begin ---

    /// One export whose WIT result is a string: copy the input into a buffer
    /// from cabi_realloc (the guest owns and frees it), call with the scalars
    /// then (ptr, len), read (ptr, len) from the return area, copy the
    /// result out, and call the post-return function exactly once, which
    /// frees it. Any failure kills the instance.
    private func call(_ name: String, _ scalars: [Value], _ input: [UInt8]) throws(HostError) -> String {
        guard !dead else { throw .trap(export: name, detail: "the instance was discarded after an earlier failure") }
        do {
            guard let f = instance.exports[function: Abi.verify + name],
                let post = instance.exports[function: "cabi_post_" + Abi.verify + name]
            else { throw HostError.abiMismatch("aprv.wasm does not export \(Abi.verify + name)") }
            guard let count = UInt32(exactly: input.count) else {
                throw HostError.unusableAnswer(export: name, detail: "the input is larger than a list<u8> can hold")
            }
            let p = try Guest.pointer(realloc.invoke([.i32(0), .i32(0), .i32(1), .i32(count)]))
            try Guest.write(memory, p, input)
            let retptr = try Guest.pointer(f.invoke(scalars + [.i32(p), .i32(count)]))
            let area = try Guest.read(memory, retptr, 8)
            let out = try Guest.read(memory, Guest.u32(area, 0), Guest.u32(area, 4))
            _ = try post.invoke([.i32(retptr)])
            guard let text = String(validating: out, as: UTF8.self) else {
                throw HostError.unusableAnswer(export: name, detail: "the answer is not UTF-8")
            }
            return text
        } catch let error as HostError {
            dead = true
            throw error
        } catch {
            dead = true
            throw .trap(export: name, detail: String(describing: error))
        }
    }

    static func pointer(_ results: [Value]) throws(HostError) -> UInt32 {
        guard results.count == 1, case .i32(let p) = results[0] else {
            throw .unusableAnswer(export: "cabi", detail: "expected one i32 result, got \(results)")
        }
        return p
    }

    static func write(_ memory: Memory, _ p: UInt32, _ bytes: [UInt8]) throws(HostError) {
        guard UInt64(p) + UInt64(bytes.count) <= UInt64(memory.byteCount) else {
            throw .unusableAnswer(export: "cabi", detail: "a write of \(bytes.count) bytes at \(p) is outside memory")
        }
        guard !bytes.isEmpty else { return }
        memory.withUnsafeMutableBufferPointer(offset: UInt(p), count: bytes.count) { to in
            bytes.withUnsafeBytes { to.copyMemory(from: $0) }
        }
    }

    static func read(_ memory: Memory, _ p: UInt32, _ n: UInt32) throws(HostError) -> [UInt8] {
        guard UInt64(p) + UInt64(n) <= UInt64(memory.byteCount) else {
            throw .unusableAnswer(export: "cabi", detail: "a read of \(n) bytes at \(p) is outside memory")
        }
        return n == 0 ? [] : memory.withUnsafeBufferPointer(offset: UInt(p), count: Int(n)) { [UInt8]($0) }
    }

    static func le(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(truncatingIfNeeded: v >> (8 * $0)) } }

    static func u32(_ bytes: [UInt8], _ at: Int) -> UInt32 {
        (0..<4).reduce(UInt32(0)) { $0 | UInt32(bytes[at + $1]) << (8 * $1) }
    }

    // --- canonical ABI (hand-written) end ---

    /// random-get's default source: the platform CSPRNG behind
    /// `SystemRandomNumberGenerator`.
    static let systemRandomBytes: @Sendable (Int) -> [UInt8] = { n in
        var rng = SystemRandomNumberGenerator()
        var out = [UInt8]()
        out.reserveCapacity(n)
        while out.count < n {
            let word = rng.next()
            for i in 0..<min(8, n - out.count) { out.append(UInt8(truncatingIfNeeded: word >> (8 * UInt64(i)))) }
        }
        return out
    }
}
