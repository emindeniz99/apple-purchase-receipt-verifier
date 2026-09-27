import X509

/// ``Verifier/verifyReceiptEndpoint(environment:requestJson:)``: a local
/// stand-in for Apple's deprecated `verifyReceipt` endpoint. Same request
/// body, same response body, same status codes, but verified offline against
/// the pinned roots instead of by calling Apple.
///
/// Fields that exist only in Apple's server-side database, such as
/// `latest_receipt_info` and `pending_renewal_info`, are not produced. Like
/// Apple's endpoint, it checks no bundle id: the caller compares
/// `receipt.bundle_id`.

/// The request body cap, in UTF-8 bytes: 3 MiB, Apple's own limit.
public let maxEndpointRequestBytes = 3_145_728

func verifyReceiptEndpoint(
    environment: Environment, requestJson: String, roots: [Certificate], clock: @Sendable () -> Int64
) -> String {
    guard !roots.isEmpty else { return statusOnly(endpointStatus(for: .internalError)) }
    let verifiedOutcome: Result<ReceiptPayload, Failure> = {
        do {
            let data = try receiptDataField(requestJson)
            let result = verifyReceipt(base64: data, roots: roots, clock: clock)
            if let payload = result.payload { return .success(payload) }
            return .failure(result.failure ?? Failure(.internalError, "unexpected internal failure"))
        } catch let failure as Failure {
            return .failure(failure)
        } catch {
            return .failure(Failure(.malformed, "unexpected failure while reading unverified input"))
        }
    }()
    switch verifiedOutcome {
    case .failure(let failure):
        return statusOnly(endpointStatus(for: failure.reason))
    case .success(let payload):
        let production = Environment.fromReceiptType(payload.receiptType) == .production
        let status: Int
        switch environment {
        case .production where !production: status = AppleStatus.sandboxReceiptOnProduction
        case .sandbox where production: status = AppleStatus.productionReceiptOnSandbox
        default: status = AppleStatus.ok
        }
        guard status == AppleStatus.ok else { return statusOnly(status) }
        return renderEndpointResponse(environment: environment, receipt: payload, requestDateMillis: clock())
    }
}

private func endpointStatus(for reason: Reason) -> Int {
    switch reason {
    case .malformed, .tooLarge: return AppleStatus.malformedReceiptData
    case .invalidSignature, .untrustedChain, .invalidCertificate, .invalidCertificatePurpose:
        return AppleStatus.receiptNotAuthenticated
    case .unreadablePayload, .internalError: return AppleStatus.internalDataAccessError
    }
}

private func statusOnly(_ status: Int) -> String { "{\"status\":\(status)}" }

/// The `receipt-data` string of a request body. A body over
/// ``maxEndpointRequestBytes`` is ``Reason/tooLarge``; a body that is not a
/// JSON object (unparseable, empty, an array, a scalar) or nests deeper than
/// 64, and a `receipt-data` that is missing or not a string, are
/// ``Reason/malformed``.
///
/// The whole object is read, so a body that breaks after `receipt-data` is
/// still refused, and the LAST `receipt-data` wins, as it would in a map.
/// Anything after the object is not read. `password` and
/// `exclude-old-transactions` are read and ignored (by simply not being
/// looked at here).
private func receiptDataField(_ requestJson: String) throws -> String {
    guard requestJson.utf8.count <= maxEndpointRequestBytes else {
        throw Failure(.tooLarge, "request body exceeds the maximum of \(maxEndpointRequestBytes) bytes")
    }
    let members: [(String, JsonValue)]
    do {
        members = try topLevelMembers(requestJson)
    } catch {
        throw Failure(.malformed, "request body is not valid JSON")
    }
    var receiptData: String?
    for (name, value) in members where name == "receipt-data" {
        if case .string(let text) = value { receiptData = text } else { receiptData = nil }
    }
    guard let receiptData else { throw Failure(.malformed, "receipt-data is missing or not a string") }
    return receiptData
}

/// The status-0 response. Keys and value types follow Apple's endpoint; key
/// order is deterministic but not part of the contract.
/// `in_app_ownership_type` and everything that lives only in Apple's
/// server-side database are never present.
private func renderEndpointResponse(environment: Environment, receipt: ReceiptPayload, requestDateMillis: Int64)
    -> String
{
    var out = ""
    let response = JsonObjectWriter.open(into: { out += $0 })
    response.number("status", Int64(AppleStatus.ok))
    response.string("environment", environment.appleValue)
    response.key("receipt")
    var receiptFragment = ""
    writeReceiptResponse(receipt: receipt, requestDateMillis: requestDateMillis, into: { receiptFragment += $0 })
    response.raw(receiptFragment)
    response.close()
    return out
}

private func writeReceiptResponse(
    receipt: ReceiptPayload, requestDateMillis: Int64, into target: @escaping (String) -> Void
) {
    let json = JsonObjectWriter.open(into: target)
    presentString(json, "receipt_type", receipt.receiptType)
    // Apple echoes attribute 1 under both names (its response reference
    // defines adam_id as "See app_item_id") and as JSON numbers, not as the
    // strings the in-app integers are rendered with.
    presentNumber(json, "adam_id", receipt.appItemId)
    presentNumber(json, "app_item_id", receipt.appItemId)
    presentString(json, "bundle_id", receipt.bundleId)
    presentString(json, "application_version", receipt.applicationVersion)
    presentNumber(json, "download_id", receipt.downloadId)
    presentNumber(json, "version_external_identifier", receipt.versionExternalIdentifier)
    presentString(json, "original_application_version", receipt.originalApplicationVersion)
    appleDates(json, "receipt_creation_date", receipt.receiptCreationDateMs)
    appleDates(json, "request_date", requestDateMillis)
    appleDates(json, "original_purchase_date", receipt.originalPurchaseDateMs)
    appleDates(json, "expiration_date", receipt.expirationDateMs)
    json.key("in_app")
    json.raw("[")
    for (index, purchase) in receipt.inApp.enumerated() {
        if index > 0 { json.raw(",") }
        var fragment = ""
        writePurchaseResponse(purchase, into: { fragment += $0 })
        json.raw(fragment)
    }
    json.raw("]")
    json.close()
}

private func writePurchaseResponse(_ purchase: InAppPurchase, into target: @escaping (String) -> Void) {
    let json = JsonObjectWriter.open(into: target)
    if let quantity = purchase.quantity {
        json.string("quantity", String(quantity))
    }
    presentString(json, "product_id", purchase.productId)
    presentString(json, "transaction_id", purchase.transactionId)
    presentString(json, "original_transaction_id", purchase.originalTransactionId)
    appleDates(json, "purchase_date", purchase.purchaseDateMs)
    appleDates(json, "original_purchase_date", purchase.originalPurchaseDateMs)
    appleDates(json, "expires_date", purchase.expiresDateMs)
    appleDates(json, "cancellation_date", purchase.cancellationDateMs)
    // Apple omits the key when attribute 1711 is 0, as it is for
    // consumables.
    if let id = purchase.webOrderLineItemId, id != 0 {
        json.string("web_order_line_item_id", String(id))
    }
    if let flag = purchase.isTrialPeriod {
        json.string("is_trial_period", flag ? "true" : "false")
    }
    if let flag = purchase.isInIntroOfferPeriod {
        json.string("is_in_intro_offer_period", flag ? "true" : "false")
    }
    json.close()
}

private func presentString(_ json: JsonObjectWriter, _ key: String, _ value: String?) {
    if let value { json.string(key, value) }
}

private func presentNumber(_ json: JsonObjectWriter, _ key: String, _ value: Int64?) {
    if let value { json.number(key, value) }
}

/// Apple's three renderings of every date: `x` in GMT, `x_ms` in epoch
/// milliseconds (as a string), and `x_pst` in US Pacific time.
private func appleDates(_ json: JsonObjectWriter, _ prefix: String, _ millis: Int64?) {
    guard let millis else { return }
    json.string(prefix, formatEtcGMT(millis: millis))
    json.string("\(prefix)_ms", String(millis))
    json.string("\(prefix)_pst", formatPacific(millis: millis))
}
