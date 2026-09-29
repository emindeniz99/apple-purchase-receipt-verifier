import Foundation
import WasmKit

/// aprv.wasm parsed once, with the engine that runs it. Both are `Sendable`
/// and shared by every ``Verifier`` of the process; stores and instances are
/// not, and belong to one ``Guest`` each.
struct AprvModule: Sendable {
    let engine: Engine
    let module: Module

    /// The engine's configuration. Bounds checking is software, requested
    /// explicitly: WasmKit's default on Linux and macOS is the mprotect mode,
    /// which reserves guard regions and installs a process-wide SIGSEGV and
    /// SIGBUS handler that jumps out of the interpreter. A library running in
    /// its caller's process takes neither; the software checks are what iOS
    /// and every other platform use anyway (THREAT-MODEL.md §2, class A).
    static let configuration = EngineConfiguration(memoryBoundsChecking: .software)

    /// The bundled module, loaded on first use: read, checked against
    /// aprv.wasm.sha256, parsed and checked against the ABI once per process.
    static let bundled: Result<AprvModule, HostError> = Result { () throws(HostError) in
        guard let wasmURL = resource("aprv.wasm"), let sumURL = resource("aprv.wasm.sha256"),
            let wasm = try? Data(contentsOf: wasmURL), let sum = try? String(contentsOf: sumURL, encoding: .utf8)
        else { throw .moduleUnavailable("the package's aprv.wasm or aprv.wasm.sha256 resource is missing") }
        return try load([UInt8](wasm), sumFile: sum)
    }

    /// One of the package's two resources, aprv.wasm and aprv.wasm.sha256.
    static func resource(_ name: String) -> URL? {
        Bundle.module.url(forResource: name, withExtension: nil)
    }

    /// `bytes`, after checking them against `sumFile` (sha256sum's format,
    /// so `sha256sum -c aprv.wasm.sha256` checks the same claim from a shell).
    static func load(_ bytes: [UInt8], sumFile: String) throws(HostError) -> AprvModule {
        let want = String(sumFile.prefix { !$0.isWhitespace }).lowercased()
        let got = SHA256.hex(bytes)
        guard want.count == 64, got == want else {
            throw .moduleUnavailable("aprv.wasm has SHA-256 \(got), but aprv.wasm.sha256 records \(want)")
        }
        return try load(bytes)
    }

    /// Parses `bytes` and refuses a module this package would misread: it
    /// may import only random-get, and must export the four @1.0.0
    /// operations, their post-return functions, cabi_realloc and its memory,
    /// with the core signatures the canonical ABI gives them.
    static func load(_ bytes: [UInt8], engine: EngineConfiguration = configuration) throws(HostError) -> AprvModule {
        let module: Module
        do {
            module = try parseWasm(bytes: bytes)
        } catch {
            throw .moduleUnavailable("aprv.wasm does not parse: \(error)")
        }
        let randomGet = FunctionType(parameters: [.i32, .i32], results: [])
        for entry in module.imports {
            guard entry.module == Abi.host, entry.name == "random-get", case .function(let index) = entry.descriptor,
                Int(index) < module.types.count, module.types[Int(index)] == randomGet
            else {
                throw .abiMismatch(
                    "aprv.wasm imports \(entry.module) \(entry.name); this package binds aprv:verifier@1.0.0, "
                        + "whose module imports only \(Abi.host) random-get")
            }
        }
        let loaded = AprvModule(engine: Engine(configuration: engine), module: module)
        try loaded.checkExports()
        return loaded
    }

    /// Instantiates the module once in a store of its own and checks every
    /// export the ``Guest`` calls, naming the version it expects and what
    /// the module has when one is missing or has another signature.
    private func checkExports() throws(HostError) {
        let store = Store(engine: engine)
        var imports = Imports()
        imports.define(module: Abi.host, name: "random-get", Function(store: store, parameters: [.i32, .i32]) { _, _ in [] })
        let instance: Instance
        do {
            instance = try module.instantiate(store: store, imports: imports)
        } catch {
            throw .abiMismatch("instantiating aprv.wasm failed: \(error)")
        }
        let have = module.exports.map(\.name).sorted().joined(separator: ", ")
        func want(_ name: String, _ parameters: [ValueType], _ results: [ValueType]) throws(HostError) {
            guard let f = instance.exports[function: name], f.type == FunctionType(parameters: parameters, results: results)
            else {
                throw .abiMismatch(
                    "aprv.wasm does not export \(name) with the signature this package binds "
                        + "(aprv:verifier@1.0.0); the module exports [\(have)]")
            }
        }
        try want("cabi_realloc", [.i32, .i32, .i32, .i32], [.i32])
        for (name, scalars) in Abi.exports {
            try want(Abi.verify + name, scalars + [.i32, .i32], [.i32])
            try want("cabi_post_" + Abi.verify + name, [.i32], [])
        }
        if instance.exports[function: "_initialize"] != nil { try want("_initialize", [], []) }
        guard instance.exports[memory: "memory"] != nil else {
            throw .abiMismatch("aprv.wasm exports no memory; the module exports [\(have)]")
        }
    }
}
