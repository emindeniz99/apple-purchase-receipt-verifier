import Foundation

/// The instances of one ``Verifier`` (docs/rust-core/ARCHITECTURE.md §5).
///
/// Every instance ran init with the pool's configuration once, when it was
/// created, so the roots are parsed once per instance. One instance serves
/// one call at a time: a call takes an idle instance or creates one, and
/// gives it back afterwards. An instance whose call failed inside the guest
/// is discarded with everything in it, and so is one whose memory grew past
/// ``maxPooledMemory``. Instances go when the pool does: nothing to close.
final class Pool: @unchecked Sendable {
    /// A hostile input can grow an instance's memory, and linear memory
    /// never shrinks; such an instance is dropped rather than kept for the
    /// next caller.
    static let maxPooledMemory = 64 << 20

    let module: Result<AprvModule, HostError>
    let config: [UInt8]
    private let random: @Sendable (Int) -> [UInt8]
    private let maxIdle: Int
    private let lock = NSLock()
    private var idle: [Guest] = []

    init(
        module: Result<AprvModule, HostError>, config: [UInt8],
        random: @escaping @Sendable (Int) -> [UInt8] = Guest.systemRandomBytes
    ) {
        self.module = module
        self.config = config
        self.random = random
        self.maxIdle = max(ProcessInfo.processInfo.activeProcessorCount, 1)
    }

    /// Runs `body` on an instance that nothing else is using.
    func with<T>(_ body: (Guest) throws(HostError) -> T) throws(HostError) -> T {
        let guest = try take()
        defer { give(guest) }
        return try body(guest)
    }

    /// A new instance after a successful init, holding the input length its
    /// answer stated, or the error that stopped it:
    /// ``HostError/initRefused(message:)`` when the module refuses the
    /// configuration, ``HostError/unusableAnswer(export:detail:)`` when the
    /// answer states no input length (a module of another ABI version).
    func create() throws(HostError) -> Guest {
        let guest = try Guest(module.get(), random: random)
        try guest.start(config)
        return guest
    }

    /// How many instances wait for the next call.
    var idleCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return idle.count
    }

    private func take() throws(HostError) -> Guest {
        lock.lock()
        let guest = idle.popLast()
        lock.unlock()
        if let guest { return guest }
        return try create()
    }

    private func give(_ guest: Guest) {
        guard !guest.dead, guest.memoryBytes <= Self.maxPooledMemory else { return }
        lock.lock()
        if idle.count < maxIdle { idle.append(guest) }
        lock.unlock()
    }
}
