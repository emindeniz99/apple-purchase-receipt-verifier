import Foundation

/// The system clock, as epoch milliseconds.
@Sendable func systemMillis() -> Int64 {
    Int64((Date().timeIntervalSince1970 * 1000).rounded(.towardZero))
}

/// A programming mistake in how a ``Config`` was built: no trust anchors,
/// or a configuration the verification module refuses (a root that is not a
/// certificate, or a revocation setting, see ``Config``). Thrown by
/// ``Verifier/init(config:)``, which creates one module instance at startup
/// to check the configuration. Not a ``Failure``: misconfiguration is not a
/// verdict about any input, and happens once, at startup. Also thrown when
/// the verification module this package carries cannot be loaded at all.
public struct ConfigError: Error, Sendable, CustomStringConvertible {
    public let detail: String
    init(_ detail: String) { self.detail = detail }
    public var description: String { detail }
}

/// One certificate to refuse, named by its revocation key: the issuer id of
/// the certificate that issued it, and its serial number
/// (docs/design/revocation.md §2). It holds both strings exactly as given;
/// the verification module checks and normalises them when the
/// ``Verifier`` is built.
public struct RevokedCertificate: Sendable, Hashable {
    /// The issuer id: the SHA-256, in hex, of the issuing certificate's
    /// subject Name followed by its subjectPublicKeyInfo, both as encoded in
    /// that certificate. 64 hex digits.
    public let issuer: String
    /// The revoked certificate's serial number in hex, either letter case,
    /// with or without leading zeros.
    public let serial: String

    public init(issuer: String, serial: String) {
        self.issuer = issuer
        self.serial = serial
    }
}

/// What a ``Verifier`` is built from: the pinned roots, the revocation
/// settings and the clock.
///
/// The clock answers "what time is it now?" and nothing else. The library
/// reads it once per call, before it looks at the input, and the
/// verification module uses the value in three places: the chain check when
/// the receipt or JWS carries no signing date, `request_date` in the
/// endpoint response, and whether a revocation list is still fresh when it
/// holds a `certificateHold` entry for a certificate on the path. A
/// caller-supplied clock must be safe to call from several threads — it is
/// typed `@Sendable` — and must not answer a time before 1970, which is
/// ``Reason/internalError``.
///
/// The revocation settings are three layers' inputs (the list built into
/// the module is the fourth source and is always on): Apple's revocation
/// lists, which you download yourself from ``Verifier/revocationUrls`` and
/// pass as bytes; the certificates that sign such lists, beyond the ones
/// the module knows; and certificates you refuse by name. Each is empty by
/// default. The module judges all three when the ``Verifier`` is built.
public struct Config: Sendable {
    /// The roots a chain must reach, as DER-encoded certificates, or `nil`
    /// for Apple's three published roots, which are compiled into the
    /// verification module and pinned there.
    public let roots: [[UInt8]]?
    /// Certificate revocation lists (CRLs) exactly as downloaded (DER), in
    /// any order: at most 16, each at most 1 MiB.
    public let revocationLists: [[UInt8]]
    /// CA certificates that sign revocation lists, added to the ones built
    /// into the module, in the same form as ``roots``.
    public let revocationIssuers: [[UInt8]]
    /// Certificates to refuse, at most 1,000.
    public let distrust: [RevokedCertificate]
    let clock: @Sendable () -> Int64

    /// The configuration, built one way. `nil` for `roots` or `clock` means
    /// its default: Apple's three published roots, and the system clock. The
    /// revocation settings default to empty. It stores what it is given;
    /// ``Verifier/init(config:)`` checks it.
    ///
    /// - Parameters:
    ///   - roots: The roots a chain must reach, replacing Apple's, as
    ///     DER-encoded certificates. Tests use their own.
    ///   - revocationLists: Revocation lists exactly as downloaded (DER),
    ///     from the URLs ``Verifier/revocationUrls`` names. A list that is
    ///     not a CRL, is signed by no issuer the verifier knows, or is older
    ///     than the one this release was built with is refused; a genuine
    ///     list in a form the module does not support is ignored.
    ///   - revocationIssuers: CA certificates that sign revocation lists,
    ///     as DER or PEM bytes: a new Apple intermediate, or a test PKI's.
    ///     Each must chain to a configured root.
    ///   - distrust: Certificates to refuse, by issuer id and serial.
    ///   - clock: The clock, as a closure returning epoch milliseconds.
    ///     Must be safe to call from several threads.
    public init(
        roots: [[UInt8]]? = nil, revocationLists: [[UInt8]] = [], revocationIssuers: [[UInt8]] = [],
        distrust: [RevokedCertificate] = [], clock: (@Sendable () -> Int64)? = nil
    ) {
        self.roots = roots
        self.revocationLists = revocationLists
        self.revocationIssuers = revocationIssuers
        self.distrust = distrust
        self.clock = clock ?? systemMillis
    }

    /// The check ``Verifier/init(config:)`` makes before it hands the
    /// configuration to a module instance: an empty root set is refused,
    /// since a verifier with no roots would answer ``Reason/untrustedChain``
    /// to everything and nobody would notice until production.
    func check() throws {
        if roots?.isEmpty == true {
            throw ConfigError("roots must not be empty")
        }
    }

    /// init's argument (docs/rust-core/ARCHITECTURE.md §4,
    /// docs/design/revocation.md §8).
    var initJson: [UInt8] {
        Config.initJson(roots, revocationLists: revocationLists, revocationIssuers: revocationIssuers, distrust: distrust)
    }

    /// init's argument, written by Foundation's `JSONEncoder`: `roots`,
    /// `revocation_lists` and `revocation_issuers` as lists of byte strings,
    /// `distrust` as `{"issuer":...,"serial":...}` objects with the strings
    /// as given. `Data` encodes as padded standard base64; slashes stay
    /// unescaped, so the text reads as the other ports write it (the module
    /// would read `\/` as `/` all the same), and the members are written in
    /// sorted order so the bytes are the same on every platform. `nil`
    /// roots and an empty revocation setting leave the member out: `{}` is
    /// the built-in roots and no revocation settings.
    static func initJson(
        _ roots: [[UInt8]]?, revocationLists: [[UInt8]] = [], revocationIssuers: [[UInt8]] = [],
        distrust: [RevokedCertificate] = []
    ) -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes, .sortedKeys]
        let lists = revocationLists.isEmpty ? nil : revocationLists.map { Data($0) }
        let issuers = revocationIssuers.isEmpty ? nil : revocationIssuers.map { Data($0) }
        let entries = distrust.isEmpty ? nil : distrust.map { InitConfig.Distrusted(issuer: $0.issuer, serial: $0.serial) }
        let anchors = roots?.map { Data($0) }
        let config = InitConfig(roots: anchors, revocationLists: lists, revocationIssuers: issuers, distrust: entries)
        guard let data = try? encoder.encode(config) else {
            preconditionFailure("JSONEncoder refused the configuration")
        }
        return Array(data)
    }
}

/// init's configuration (rust/bindings/wire/schema/init-config.schema.json).
private struct InitConfig: Encodable {
    struct Distrusted: Encodable {
        let issuer: String
        let serial: String
    }

    let roots: [Data]?
    let revocationLists: [Data]?
    let revocationIssuers: [Data]?
    let distrust: [Distrusted]?

    enum CodingKeys: String, CodingKey {
        case roots, revocationLists = "revocation_lists", revocationIssuers = "revocation_issuers", distrust
    }
}
