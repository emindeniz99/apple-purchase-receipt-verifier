import Foundation

/// The system clock, as epoch milliseconds.
@Sendable func systemMillis() -> Int64 {
    Int64((Date().timeIntervalSince1970 * 1000).rounded(.towardZero))
}

/// A programming mistake in how a ``Config`` was built: no trust anchors, or
/// bytes the verification module refuses as a certificate. Thrown by
/// ``Verifier/init(config:)``, which creates one module instance at startup
/// when roots are given. Not a ``Failure``: misconfiguration is not a
/// verdict about any input, and happens once, at startup. Also thrown when
/// the verification module this package carries cannot be loaded at all.
public struct ConfigError: Error, Sendable, CustomStringConvertible {
    public let detail: String
    init(_ detail: String) { self.detail = detail }
    public var description: String { detail }
}

/// What a ``Verifier`` is built from: the pinned roots and the clock.
///
/// The clock answers "what time is it now?" and nothing else. The library
/// reads it once per call, before it looks at the input, and the
/// verification module uses the value in two places: the chain check when
/// the receipt or JWS carries no signing date, and `request_date` in the
/// endpoint response. A caller-supplied clock must be safe to call from
/// several threads — it is typed `@Sendable` — and must not answer a time
/// before 1970, which is ``Reason/internalError``.
public struct Config: Sendable {
    /// The roots a chain must reach, as DER-encoded certificates, or `nil`
    /// for Apple's three published roots, which are compiled into the
    /// verification module and pinned there.
    public let roots: [[UInt8]]?
    let clock: @Sendable () -> Int64

    /// The configuration, built one way. `nil` for either argument means
    /// its default: Apple's three published roots, and the system clock.
    /// It stores what it is given; ``Verifier/init(config:)`` checks it.
    ///
    /// - Parameters:
    ///   - roots: The roots a chain must reach, replacing Apple's, as
    ///     DER-encoded certificates. Tests use their own.
    ///   - clock: The clock, as a closure returning epoch milliseconds.
    ///     Must be safe to call from several threads.
    public init(roots: [[UInt8]]? = nil, clock: (@Sendable () -> Int64)? = nil) {
        self.roots = roots
        self.clock = clock ?? systemMillis
    }

    /// The startup check ``Verifier/init(config:)`` makes: an empty root
    /// set is refused, since a verifier with no roots would answer
    /// ``Reason/untrustedChain`` to everything and nobody would notice
    /// until production; and the roots are handed to a fresh module
    /// instance, so one the module refuses is a ``ConfigError`` at startup
    /// rather than a verdict on the first call.
    func check() throws {
        guard let roots else { return }
        if roots.isEmpty {
            throw ConfigError("roots must not be empty")
        }
        do {
            _ = try Pool(module: AprvModule.bundled, config: Config.initJson(roots)).create()
        } catch .initRefused(let message) {
            throw ConfigError("trust anchor is not a certificate: \(message)")
        } catch {
            throw ConfigError("the verification module could not check the trust anchors: \(error)")
        }
    }

    /// init's argument (docs/rust-core/ARCHITECTURE.md §4): the roots as
    /// base64 DER, where an empty list means the module's built-in roots.
    var initJson: [UInt8] {
        Config.initJson(roots ?? [])
    }

    /// init's argument for `roots`, written by Foundation's `JSONEncoder`.
    /// `Data` encodes as padded standard base64; slashes stay unescaped, so
    /// the text is `{"roots":["<base64>",...]}` as the other ports write it
    /// (the module would read `\/` as `/` all the same).
    static func initJson(_ roots: [[UInt8]]) -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .withoutEscapingSlashes
        guard let data = try? encoder.encode(InitConfig(roots: roots.map { Data($0) })) else {
            preconditionFailure("JSONEncoder refused a list of byte strings")
        }
        return Array(data)
    }
}

/// init's configuration (rust/bindings/wire/schema/init-config.schema.json).
private struct InitConfig: Encodable {
    let roots: [Data]
}
