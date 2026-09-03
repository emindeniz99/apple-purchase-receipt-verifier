import Foundation
import X509

/// Drop-in local replacement for Apple's deprecated `verifyReceipt`
/// endpoint: same request body, same response body shape, same status
/// codes — but verified offline against the pinned Apple root instead of by
/// calling Apple. Field-by-field fidelity and the unavoidable gaps (fields
/// that only exist in Apple's server-side subscription database, like
/// `latest_receipt_info` / `pending_renewal_info`) are documented in
/// COMPARISON.md.
///
/// Like Apple's endpoint, this does NOT check the bundle id — the caller
/// compares `receipt["bundle_id"]`, exactly as with the real endpoint.
public struct VerifyReceiptEndpoint: Sendable {
    public static let statusOK = 0
    /// Malformed request or receipt-data property.
    public static let statusMalformed = 21002
    /// Receipt could not be authenticated.
    public static let statusNotAuthenticated = 21003
    /// Sandbox receipt sent to the production environment.
    public static let statusSandboxReceiptOnProduction = 21007
    /// Production receipt sent to the sandbox environment.
    public static let statusProductionReceiptOnSandbox = 21008
    /// Internal error.
    public static let statusInternal = 21009

    private let roots: [Certificate]
    private let environment: AppleEnvironment
    private let clock: @Sendable () -> Date

    /// - Parameters:
    ///   - trustedRoots: pinned DER roots (production: ``appleReceiptRoots()``)
    ///   - environment: which environment this instance emulates
    ///     (drives 21007/21008 routing). ``AppleEnvironment/production`` or
    ///     ``AppleEnvironment/sandbox`` — Apple's verifyReceipt endpoint has
    ///     no other environment to emulate, and the two it does not name
    ///     (`Xcode`, `LocalTesting`) are rejected here rather than folded into
    ///     one of them. This is the `environment` enum node, python and
    ///     fixtures/cases.json use; the boolean overload below is the older
    ///     spelling of the same option.
    ///   - clock: the source of "now" for the response's `request_date`
    ///     fields, which Apple's endpoint stamps with the wall-clock time the
    ///     request was served. Same type and same meaning as
    ///     ``JwsVerifier/init(trustedRoots:bundleId:acceptedEnvironments:appAppleId:maxSignedAgeMillis:clock:)``:
    ///     omitted, the system clock is read. It moves no verdict — the
    ///     status code and every verified field are unaffected. In particular
    ///     it never reaches a certificate-validity decision: the receipt path
    ///     takes no clock at all, and judges chain validity at the receipt's
    ///     creation date, falling back to the system clock.
    public init(trustedRoots: [Data], environment: AppleEnvironment,
                clock: (@Sendable () -> Date)? = nil) throws {
        guard environment == .production || environment == .sandbox else {
            throw VerificationError(.wrongEnvironment,
                "verifyReceipt emulates Production or Sandbox, not \(environment.rawValue)")
        }
        guard !trustedRoots.isEmpty else {
            throw VerificationError(.invalidCertificate, "trustedRoots is required")
        }
        // No ReceiptVerifier, and so no bundle id: the endpoint accepts any
        // bundle exactly as Apple's does (callers compare bundle_id), and
        // ``ReceiptVerifier/verifyCore(receipt:trustedRoots:)`` is that
        // primitive without the claim check. It used to hold a verifier built
        // with a wildcard bundle id — a stand-in for a check that never ran.
        self.roots = try trustedRoots.map { try Certificate(derEncoded: [UInt8]($0)) }
        self.environment = environment
        self.clock = clock ?? { Date() }
    }

    /// Boolean spelling of ``init(trustedRoots:environment:clock:)``, kept
    /// working for callers written against it.
    @available(*, deprecated,
               message: "use init(trustedRoots:environment:clock:) with .production / .sandbox")
    public init(trustedRoots: [Data], production: Bool,
                clock: (@Sendable () -> Date)? = nil) throws {
        try self.init(trustedRoots: trustedRoots,
                      environment: production ? .production : .sandbox, clock: clock)
    }

    /// Handles one verifyReceipt request body. Never throws — like the real
    /// endpoint, failures are reported through `status`.
    public func verifyReceipt(_ requestBody: [String: Any]?) async -> [String: Any] {
        guard let receiptData = requestBody?["receipt-data"] as? String, !receiptData.isEmpty,
              let der = Data(base64Encoded: receiptData, options: [.ignoreUnknownCharacters]) else {
            return ["status": Self.statusMalformed]
        }
        let fields: AppReceipt
        do {
            fields = try await ReceiptVerifier.verifyCore(receipt: der, roots: roots)
        } catch let error as VerificationError {
            return ["status": error.reason == .invalidReceiptFormat
                ? Self.statusMalformed : Self.statusNotAuthenticated]
        } catch {
            return ["status": Self.statusInternal]
        }

        // 21007/21008 environment routing from the receipt_type attribute.
        // Production types are exactly "Production" and "ProductionVPP";
        // everything else ("ProductionSandbox", "ProductionVPPSandbox",
        // "Xcode", or a missing attribute) fails closed as non-production.
        // "Xcode" is listed for completeness only: an Xcode-generated
        // receipt is not Apple-signed, so it fails chain verification with
        // 21003 above and never reaches this branch.
        let productionReceipt = fields.receiptType == "Production"
            || fields.receiptType == "ProductionVPP"
        if environment == .production && !productionReceipt {
            return ["status": Self.statusSandboxReceiptOnProduction]
        }
        if environment == .sandbox && productionReceipt {
            return ["status": Self.statusProductionReceiptOnSandbox]
        }
        return [
            "status": Self.statusOK,
            "environment": environment.rawValue,
            "receipt": receiptJson(fields, requestDate: clock()),
        ]
    }

    /// Handles one verifyReceipt request body in its raw wire form: the
    /// JSON request body in, the JSON response body out, so an HTTP
    /// framework's body can be piped straight through without a DTO in
    /// between. A thin wrapper over ``verifyReceipt(_:)`` — every
    /// verification decision is made there.
    ///
    /// A body that is not a JSON object (unparseable, `null`, an array, a
    /// scalar) answers `{"status":21002}`. Apple has no status code for
    /// "that wasn't JSON"; 21002 ("The data in the receipt-data property
    /// was malformed or missing") is the closest, and it is what a JSON
    /// object without usable `receipt-data` gets anyway.
    ///
    /// Output is deterministic: Swift dictionaries have no insertion
    /// order, so keys are serialized sorted (`.sortedKeys`). Key order is
    /// not part of the JSON contract — only the bytes being reproducible
    /// is.
    public func verifyReceiptJSON(_ body: String) async -> String {
        guard let data = body.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data),
              let requestBody = parsed as? [String: Any] else {
            return "{\"status\":\(Self.statusMalformed)}"
        }
        let response = await verifyReceipt(requestBody)
        guard let encoded = try? JSONSerialization.data(
                withJSONObject: response, options: [.sortedKeys]),
              let json = String(data: encoded, encoding: .utf8) else {
            return "{\"status\":\(Self.statusInternal)}"
        }
        return json
    }
}

private func receiptJson(_ fields: AppReceipt, requestDate: Date) -> [String: Any] {
    var json: [String: Any] = [:]
    put(&json, "receipt_type", fields.receiptType)
    put(&json, "bundle_id", fields.bundleId)
    put(&json, "application_version", fields.appVersion)
    put(&json, "original_application_version", fields.originalAppVersion)
    appleDates(&json, "receipt_creation_date", fields.creationDate)
    appleDates(&json, "request_date", requestDate)
    appleDates(&json, "original_purchase_date", fields.originalPurchaseDate)
    appleDates(&json, "expiration_date", fields.expirationDate)
    json["in_app"] = fields.inAppPurchases.map(inAppJson)
    return json
}

private func inAppJson(_ purchase: InAppPurchase) -> [String: Any] {
    var json: [String: Any] = [:]
    put(&json, "quantity", purchase.quantity.map(String.init))
    put(&json, "product_id", purchase.productId)
    put(&json, "transaction_id", purchase.transactionId)
    put(&json, "original_transaction_id", purchase.originalTransactionId)
    appleDates(&json, "purchase_date", purchase.purchaseDate)
    appleDates(&json, "original_purchase_date", purchase.originalPurchaseDate)
    appleDates(&json, "expires_date", purchase.expiresDate)
    appleDates(&json, "cancellation_date", purchase.cancellationDate)
    put(&json, "web_order_line_item_id", purchase.webOrderLineItemId.map(String.init))
    if let intro = purchase.isInIntroOfferPeriod {
        json["is_in_intro_offer_period"] = intro == 1 ? "true" : "false"
    }
    return json
}

private func put(_ json: inout [String: Any], _ key: String, _ value: Any?) {
    if let value {
        json[key] = value
    }
}

/// Apple's three date renderings: `x` (GMT), `x_ms` (epoch ms), `x_pst`.
private func appleDates(_ json: inout [String: Any], _ prefix: String, _ date: Date?) {
    guard let date else { return }
    json[prefix] = format(date, zone: TimeZone(identifier: "UTC")!) + " Etc/GMT"
    json["\(prefix)_ms"] = String(Int64(date.timeIntervalSince1970 * 1000))
    json["\(prefix)_pst"] = format(date, zone: TimeZone(identifier: "America/Los_Angeles")!)
        + " America/Los_Angeles"
}

private func format(_ date: Date, zone: TimeZone) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = zone
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return formatter.string(from: date)
}
