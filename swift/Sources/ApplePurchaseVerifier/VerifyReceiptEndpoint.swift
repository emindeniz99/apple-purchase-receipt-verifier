import Foundation

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

    private let verifier: ReceiptVerifier
    private let production: Bool

    /// - Parameters:
    ///   - trustedRoots: pinned DER roots (production: ``appleReceiptRoots()``)
    ///   - production: which environment this instance emulates
    ///     (drives 21007/21008 routing)
    public init(trustedRoots: [Data], production: Bool) throws {
        // The bundle id is never consulted: verifyCore skips the claim
        // check, matching Apple's endpoint (callers compare bundle_id).
        self.verifier = try ReceiptVerifier(trustedRoots: trustedRoots, bundleId: "*")
        self.production = production
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
            fields = try await verifier.verifyCore(receipt: der)
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
        let productionReceipt = fields.receiptType == "Production"
            || fields.receiptType == "ProductionVPP"
        if production && !productionReceipt {
            return ["status": Self.statusSandboxReceiptOnProduction]
        }
        if !production && productionReceipt {
            return ["status": Self.statusProductionReceiptOnSandbox]
        }
        return [
            "status": Self.statusOK,
            "environment": production ? "Production" : "Sandbox",
            "receipt": receiptJson(fields, requestDate: Date()),
        ]
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
