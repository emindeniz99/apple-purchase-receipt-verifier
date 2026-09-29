import Foundation

/// The system clock, as epoch milliseconds.
@Sendable func systemMillis() -> Int64 {
    Int64((Date().timeIntervalSince1970 * 1000).rounded(.towardZero))
}

/// A programming mistake in how a ``Config`` was built: no trust anchors, or
/// bytes the verification module refuses as a certificate. Not a
/// ``Failure``: misconfiguration is not a verdict about any input, and
/// happens once, at startup. Also thrown when the verification module this
/// package carries cannot be loaded at all.
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

    fileprivate init(roots: [[UInt8]]?, clock: @escaping @Sendable () -> Int64) {
        self.roots = roots
        self.clock = clock
    }

    /// Apple's three pinned roots and the system clock. Never throws.
    public static func defaults() -> Config {
        Config(roots: nil, clock: systemMillis)
    }

    /// A builder whose unset parts are ``defaults()``.
    public static func builder() -> ConfigBuilder { ConfigBuilder() }

    /// init's argument (docs/rust-core/ARCHITECTURE.md §4): the roots as
    /// base64 DER, where an empty list means the module's built-in roots.
    var initJson: [UInt8] {
        Config.initJson(roots ?? [])
    }

    static func initJson(_ roots: [[UInt8]]) -> [UInt8] {
        let list = roots.map { "\"" + Data($0).base64EncodedString() + "\"" }.joined(separator: ",")
        return Array(#"{"roots":[\#(list)]}"#.utf8)
    }
}

/// Builds a ``Config``.
public struct ConfigBuilder: Sendable {
    private var roots: [[UInt8]]?
    private var clock: (@Sendable () -> Int64)?

    /// The roots a chain must reach, replacing Apple's bundled ones. Tests
    /// use their own, given as DER-encoded certificates.
    ///
    /// - Throws: ``ConfigError`` when the verification module refuses one of
    ///   them as a certificate, or cannot be loaded at all. The roots are
    ///   handed to a fresh module instance here, so a bad one is refused at
    ///   startup rather than on the first call.
    public func roots(_ roots: [[UInt8]]) throws -> ConfigBuilder {
        if !roots.isEmpty {
            do {
                _ = try Pool(module: AprvModule.bundled, config: Config.initJson(roots)).create()
            } catch .initRefused(let message) {
                throw ConfigError("trust anchor is not a certificate: \(message)")
            } catch {
                throw ConfigError("the verification module could not check the trust anchors: \(error)")
            }
        }
        var copy = self
        copy.roots = roots
        return copy
    }

    /// The clock, as a closure returning epoch milliseconds. Must be safe to
    /// call from several threads.
    public func clock(_ clock: @escaping @Sendable () -> Int64) -> ConfigBuilder {
        var copy = self
        copy.clock = clock
        return copy
    }

    /// The configuration.
    ///
    /// - Throws: ``ConfigError`` for an empty root set: a verifier with no
    ///   roots would answer ``Reason/untrustedChain`` to everything, and
    ///   nobody would notice until production.
    public func build() throws -> Config {
        if let roots, roots.isEmpty {
            throw ConfigError("roots must not be empty")
        }
        return Config(roots: roots, clock: clock ?? systemMillis)
    }
}
