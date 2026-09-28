import Foundation
import X509

/// The system clock, as epoch milliseconds.
@Sendable func systemMillis() -> Int64 {
    Int64((Date().timeIntervalSince1970 * 1000).rounded(.towardZero))
}

/// A programming mistake in how a ``Config`` was built: no trust anchors, or
/// bytes that are not a certificate. Not a ``Failure``: misconfiguration is
/// not a verdict about any input, and happens once, at startup.
public struct ConfigError: Error, Sendable, CustomStringConvertible {
    public let detail: String
    init(_ detail: String) { self.detail = detail }
    public var description: String { detail }
}

/// What a ``Verifier`` is built from: the pinned roots and the clock.
///
/// The clock answers "what time is it now?" and nothing else. The library
/// reads it in two places: the chain check when the receipt or JWS carries no
/// signing date, and `request_date` in the endpoint response. A
/// caller-supplied clock must be safe to call from several threads — it is
/// typed `@Sendable`.
public struct Config: Sendable {
    /// The pinned roots a chain must reach — an unmodifiable copy.
    public let roots: [Certificate]
    let clock: @Sendable () -> Int64

    fileprivate init(roots: [Certificate], clock: @escaping @Sendable () -> Int64) {
        self.roots = roots
        self.clock = clock
    }

    /// Apple's three pinned roots and the system clock.
    ///
    /// The bundled roots load all together or not at all, each checked
    /// against its published SHA-256 (``bundledAppleRoots``). Should they not
    /// load, this cannot say so: a ``Verifier`` built from it then answers
    /// ``Reason/internalError`` to every call, where ``ConfigBuilder/build()``
    /// reports a ``ConfigError`` for an empty root set given explicitly.
    public static func defaults() -> Config {
        Config(roots: bundledAppleRoots, clock: systemMillis)
    }

    /// A builder whose unset parts are ``defaults()``.
    public static func builder() -> ConfigBuilder { ConfigBuilder() }
}

/// Builds a ``Config``.
public struct ConfigBuilder: Sendable {
    private var roots: [Certificate]?
    private var clock: (@Sendable () -> Int64)?

    /// The roots a chain must reach, replacing Apple's bundled ones. Tests
    /// use their own, given as DER-encoded certificates.
    public func roots(_ roots: [[UInt8]]) throws -> ConfigBuilder {
        var copy = self
        copy.roots = try roots.map { der in
            guard let certificate = try? Certificate(derEncoded: der) else {
                throw ConfigError("trust anchor is not a certificate")
            }
            return certificate
        }
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
        let resolvedRoots = roots ?? bundledAppleRoots
        guard !resolvedRoots.isEmpty else {
            throw ConfigError("roots must not be empty")
        }
        return Config(roots: resolvedRoots, clock: clock ?? systemMillis)
    }
}
