import Foundation

/// The outcome of one ``VerifyReceiptEndpoint`` call: the Apple status, the
/// verified receipt or the reason there is none, and the Apple-shaped
/// response, rendered only when asked for.
///
/// ``outcome`` is either ``Outcome/verified(_:)`` or
/// ``Outcome/failed(reason:cause:)``, so exactly one of ``receipt`` and
/// ``failureReason`` is non-nil. The receipt is present whenever its bytes
/// verified, including when the endpoint's own environment answers 21007 or
/// 21008, so a caller can re-render for the other environment with
/// ``response(for:)`` or ``json(for:)`` without verifying twice. The status
/// is always recomputed from the receipt's own `receipt_type`, so no render
/// can answer 0 for a receipt from the wrong environment.
///
/// Immutable and `Sendable`. Only the endpoint creates one: a caller cannot
/// construct a result carrying status 0.
public struct VerifyReceiptResult: Sendable {
    /// What verification produced.
    public enum Outcome: Sendable {
        /// The receipt's signature and chain verified. Also the outcome of a
        /// 21007 or 21008 answer: those say the receipt belongs to the other
        /// environment, not that it failed to verify.
        case verified(AppReceipt)
        /// There is no receipt. `cause` is the unexpected error behind
        /// ``VerificationError/Reason/internalError`` and nil for every other
        /// reason.
        case failed(reason: VerificationError.Reason, cause: (any Error)?)
    }

    /// Verified or failed, with the receipt or the reason.
    public let outcome: Outcome
    /// The instant rendered as `request_date`, fixed when the call was made.
    public let requestDate: Date
    private let environment: AppleEnvironment

    init(environment: AppleEnvironment, outcome: Outcome, requestDate: Date) {
        self.environment = environment
        self.outcome = outcome
        self.requestDate = requestDate
    }

    /// Whether the receipt bytes verified: true exactly when ``receipt`` is
    /// non-nil. This includes 21007 and 21008 results, so it is **not** the
    /// same check as `status == 0`. `status == 0` answers "does this
    /// endpoint's own environment accept the receipt"; `isVerified` answers
    /// "did the receipt verify at all", which is what to check before
    /// trusting ``receipt``'s fields or re-rendering with ``response(for:)``.
    public var isVerified: Bool {
        if case .verified = outcome { return true }
        return false
    }

    /// The verified receipt, or nil when verification failed.
    public var receipt: AppReceipt? {
        if case .verified(let receipt) = outcome { return receipt }
        return nil
    }

    /// Why there is no receipt; non-nil exactly when ``receipt`` is nil.
    public var failureReason: VerificationError.Reason? {
        if case .failed(let reason, _) = outcome { return reason }
        return nil
    }

    /// The unexpected error behind ``VerificationError/Reason/internalError``;
    /// nil for every other outcome.
    public var failureCause: (any Error)? {
        if case .failed(_, let cause) = outcome { return cause }
        return nil
    }

    /// The Apple status for the endpoint's own environment.
    public var status: Int {
        status(for: environment)
    }

    /// The response the endpoint's own environment answers, as a new
    /// dictionary on each call. Same keys and value types as Apple's
    /// endpoint; see COMPARISON.md.
    public func response() -> [String: Any] {
        render(for: environment)
    }

    /// ``response()`` serialized as the JSON response body, keys sorted.
    public func json() -> String {
        serialize(render(for: environment))
    }

    /// The response an endpoint of `environment` would answer for the same
    /// receipt, at the same ``requestDate``. A production receipt answers 0
    /// on `.production` and 21008 on `.sandbox`; any other receipt answers
    /// 21007 on `.production` and 0 on `.sandbox`; a failed result answers
    /// its own status on both.
    ///
    /// - Throws: `VerificationError(.wrongEnvironment, …)` for `.xcode` or
    ///   `.localTesting`, as ``VerifyReceiptEndpoint/init(trustedRoots:environment:clock:)``
    ///   does.
    public func response(for environment: AppleEnvironment) throws -> [String: Any] {
        try VerifyReceiptEndpoint.requireEmulated(environment)
        return render(for: environment)
    }

    /// ``response(for:)`` serialized as the JSON response body, keys sorted.
    public func json(for environment: AppleEnvironment) throws -> String {
        serialize(try response(for: environment))
    }

    private func status(for environment: AppleEnvironment) -> Int {
        switch outcome {
        case .failed(let reason, _):
            switch reason {
            case .malformedRequest, .requestTooLarge, .invalidReceiptFormat:
                return VerifyReceiptEndpoint.statusMalformed
            case .internalError:
                return VerifyReceiptEndpoint.statusInternal
            default:
                return VerifyReceiptEndpoint.statusNotAuthenticated
            }
        case .verified(let receipt):
            // 21007/21008 environment routing from the receipt_type
            // attribute. Production types are exactly "Production" and
            // "ProductionVPP"; everything else ("ProductionSandbox",
            // "ProductionVPPSandbox", "Xcode", or a missing attribute) fails
            // closed as non-production. "Xcode" is listed for completeness
            // only: an Xcode-generated receipt is not Apple-signed, so it
            // fails chain verification with 21003 and never gets here.
            let productionReceipt =
                receipt.receiptType == "Production"
                || receipt.receiptType == "ProductionVPP"
            if environment == .production && !productionReceipt {
                return VerifyReceiptEndpoint.statusSandboxReceiptOnProduction
            }
            if environment == .sandbox && productionReceipt {
                return VerifyReceiptEndpoint.statusProductionReceiptOnSandbox
            }
            return VerifyReceiptEndpoint.statusOK
        }
    }

    private func render(for environment: AppleEnvironment) -> [String: Any] {
        let status = status(for: environment)
        guard status == VerifyReceiptEndpoint.statusOK, let receipt else {
            return ["status": status]
        }
        return [
            "status": status,
            "environment": environment.rawValue,
            "receipt": receiptJson(receipt, requestDate: requestDate),
        ]
    }

    /// Swift dictionaries have no insertion order, so keys are serialized
    /// sorted: equal inputs give equal bytes.
    private func serialize(_ response: [String: Any]) -> String {
        guard
            let encoded = try? JSONSerialization.data(
                withJSONObject: response, options: [.sortedKeys]),
            let json = String(data: encoded, encoding: .utf8)
        else {
            return "{\"status\":\(VerifyReceiptEndpoint.statusInternal)}"
        }
        return json
    }
}

private func receiptJson(_ fields: AppReceipt, requestDate: Date) -> [String: Any] {
    var json: [String: Any] = [:]
    put(&json, "receipt_type", fields.receiptType)
    // Apple echoes attribute 1 under both names — its response reference
    // defines adam_id as "See app_item_id" — and as JSON numbers, not as the
    // strings the in-app integers are rendered with. `Int64` rather than a
    // string or a `Double`: real download ids run past 2^53, and
    // JSONSerialization writes an Int64 as its exact digits.
    put(&json, "adam_id", fields.appItemId)
    put(&json, "app_item_id", fields.appItemId)
    put(&json, "bundle_id", fields.bundleId)
    put(&json, "application_version", fields.appVersion)
    put(&json, "download_id", fields.downloadId)
    put(&json, "version_external_identifier", fields.versionExternalIdentifier)
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
    if let trial = purchase.isTrialPeriod {
        json["is_trial_period"] = trial == 1 ? "true" : "false"
    }
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
    json["\(prefix)_pst"] =
        format(date, zone: TimeZone(identifier: "America/Los_Angeles")!)
        + " America/Los_Angeles"
}

private func format(_ date: Date, zone: TimeZone) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.timeZone = zone
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
    return formatter.string(from: date)
}
