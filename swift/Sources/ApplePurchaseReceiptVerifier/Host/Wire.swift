import Foundation

/// Reads the module's answers (aprv-wire, docs/rust-core/ARCHITECTURE.md
/// §4) into this package's types. It decides nothing: a verdict is whatever
/// the module wrote, and an answer that is not in the wire's shape, or names
/// a reason outside the eight, is unusable and becomes
/// ``Reason/internalError`` — this never guesses at what a module meant.
enum Wire {
    /// init's answer: `{"ok":true,"max_input_bytes":N}` or
    /// `{"ok":false,"message":"..."}`. `N` is the most bytes of one input the
    /// module needs (docs/rust-core/DECISIONS.md R42): a longer input is cut
    /// to it, and the module answers TOO_LARGE for that. An accepting answer
    /// without a positive integer there comes from a module of another ABI
    /// version, and is unusable like any answer outside the wire's shape.
    static func initAnswer(_ answer: String) throws(HostError) -> Int {
        let reply: InitReply
        do {
            reply = try JSONDecoder().decode(InitReply.self, from: Data(answer.utf8))
        } catch {
            throw .unusableAnswer(export: "init", detail: "the answer is not {\"ok\":...}: \(error)")
        }
        guard reply.ok else { throw .initRefused(message: reply.message ?? "") }
        guard let maxInputBytes = reply.maxInputBytes, maxInputBytes > 0 else {
            throw .unusableAnswer(
                export: "init",
                detail: "init accepted the configuration but states no max_input_bytes: the module is of another ABI version")
        }
        return maxInputBytes
    }

    /// A verify answer: `{"verified":true,"payload":...,"environment":<E>}`
    /// or `{"verified":false,"reason":"<Reason>","message":"..."}`, `<E>`
    /// being `"Production"`, `"Sandbox"` or `null`, the environment the
    /// module read (docs/rust-core/DECISIONS.md R42). `make` puts the payload
    /// and the environment together into the value the caller receives.
    static func result<P: Decodable & Sendable, Q: Sendable>(
        _ answer: String, _ export: String, _ payload: P.Type, _ make: (P, Environment?) -> Q
    ) -> VerificationResult<Q> {
        let envelope: Envelope<P>
        do {
            envelope = try JSONDecoder().decode(Envelope<P>.self, from: Data(answer.utf8))
        } catch {
            return unusable(export, "the answer is not a verification result: \(error)")
        }
        switch (envelope.verified, envelope.payload, envelope.reason) {
        case (true, let payload?, nil) where envelope.message == nil && envelope.statesEnvironment:
            return VerificationResult(payload: make(payload, envelope.environment))
        case (false, nil, let token?) where !envelope.statesEnvironment:
            guard let reason = Reason(rawValue: token) else {
                return unusable(export, "the reason \"\(token)\" is not one of the eight")
            }
            return VerificationResult(failure: Failure(reason, envelope.message ?? ""))
        default:
            return unusable(
                export,
                "a verified result must carry a payload and an environment and nothing else, a failed one a reason and no payload")
        }
    }

    static func unusable<P>(_ export: String, _ detail: String) -> VerificationResult<P> {
        VerificationResult(
            failure: Failure(
                .internalError, "the verification module's answer was unusable",
                cause: HostError.unusableAnswer(export: export, detail: detail)))
    }

    private struct InitReply: Decodable {
        let ok: Bool
        let message: String?
        let maxInputBytes: Int?

        enum CodingKeys: String, CodingKey { case ok, message, maxInputBytes = "max_input_bytes" }
    }

    private struct Envelope<P: Decodable>: Decodable {
        let verified: Bool
        let reason: String?
        let message: String?
        let payload: P?
        /// The member is present, `null` included.
        let statesEnvironment: Bool
        let environment: Environment?

        enum CodingKeys: String, CodingKey, CaseIterable { case verified, reason, message, payload, environment }

        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            try refuseUnknownKeys(decoder, CodingKeys.self)
            verified = try c.decode(Bool.self, forKey: .verified)
            reason = try c.decodeIfPresent(String.self, forKey: .reason)
            message = try c.decodeIfPresent(String.self, forKey: .message)
            payload = try c.decodeIfPresent(P.self, forKey: .payload)
            statesEnvironment = c.contains(.environment)
            if let token = try c.decodeIfPresent(String.self, forKey: .environment) {
                guard let environment = Environment(rawValue: token) else {
                    throw DecodingError.dataCorruptedError(
                        forKey: .environment, in: c, debugDescription: "the environment \"\(token)\" is not Production or Sandbox")
                }
                self.environment = environment
            } else {
                environment = nil
            }
        }
    }
}

/// A key the wire does not define is refused rather than skipped.
private func refuseUnknownKeys<K: CodingKey & CaseIterable>(_ decoder: any Decoder, _ keys: K.Type) throws {
    let known = Set(K.allCases.map(\.stringValue))
    for key in try decoder.container(keyedBy: AnyKey.self).allKeys where !known.contains(key.stringValue) {
        throw DecodingError.dataCorrupted(
            .init(codingPath: decoder.codingPath, debugDescription: "unknown member \(key.stringValue)"))
    }
}

private struct AnyKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}

// MARK: - the receipt payload, 0.7's "Our JSON"

extension ReceiptPayload: Decodable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case receiptType = "receipt_type", appItemId = "app_item_id", bundleId = "bundle_id"
        case bundleIdBytes = "bundle_id_bytes", applicationVersion = "application_version"
        case opaqueValue = "opaque_value", sha1Hash = "sha1_hash", receiptCreationDateMs = "receipt_creation_date_ms"
        case downloadId = "download_id", versionExternalIdentifier = "version_external_identifier", inApp = "in_app"
        case originalPurchaseDateMs = "original_purchase_date_ms"
        case originalApplicationVersion = "original_application_version", expirationDateMs = "expiration_date_ms"
        case unknownAttributes = "unknown_attributes"
    }

    public init(from decoder: any Decoder) throws {
        try refuseUnknownKeys(decoder, CodingKeys.self)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init()
        receiptType = try c.decodeIfPresent(String.self, forKey: .receiptType)
        appItemId = try c.id(.appItemId)
        bundleId = try c.decodeIfPresent(String.self, forKey: .bundleId)
        bundleIdBytes = try c.bytes(.bundleIdBytes)
        applicationVersion = try c.decodeIfPresent(String.self, forKey: .applicationVersion)
        opaqueValue = try c.bytes(.opaqueValue)
        sha1Hash = try c.bytes(.sha1Hash)
        receiptCreationDateMs = try c.decodeIfPresent(Int64.self, forKey: .receiptCreationDateMs)
        downloadId = try c.id(.downloadId)
        versionExternalIdentifier = try c.id(.versionExternalIdentifier)
        inApp = try c.decodeIfPresent([InAppPurchase].self, forKey: .inApp) ?? []
        originalPurchaseDateMs = try c.decodeIfPresent(Int64.self, forKey: .originalPurchaseDateMs)
        originalApplicationVersion = try c.decodeIfPresent(String.self, forKey: .originalApplicationVersion)
        expirationDateMs = try c.decodeIfPresent(Int64.self, forKey: .expirationDateMs)
        unknownAttributes = try c.attributes(.unknownAttributes)
    }
}

extension InAppPurchase: Decodable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case quantity, productId = "product_id", transactionId = "transaction_id", purchaseDateMs = "purchase_date_ms"
        case originalTransactionId = "original_transaction_id", originalPurchaseDateMs = "original_purchase_date_ms"
        case expiresDateMs = "expires_date_ms", webOrderLineItemId = "web_order_line_item_id"
        case cancellationDateMs = "cancellation_date_ms", isTrialPeriod = "is_trial_period"
        case isInIntroOfferPeriod = "is_in_intro_offer_period", unknownAttributes = "unknown_attributes"
    }

    public init(from decoder: any Decoder) throws {
        try refuseUnknownKeys(decoder, CodingKeys.self)
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init()
        quantity = try c.decodeIfPresent(Int64.self, forKey: .quantity)
        productId = try c.decodeIfPresent(String.self, forKey: .productId)
        transactionId = try c.decodeIfPresent(String.self, forKey: .transactionId)
        purchaseDateMs = try c.decodeIfPresent(Int64.self, forKey: .purchaseDateMs)
        originalTransactionId = try c.decodeIfPresent(String.self, forKey: .originalTransactionId)
        originalPurchaseDateMs = try c.decodeIfPresent(Int64.self, forKey: .originalPurchaseDateMs)
        expiresDateMs = try c.decodeIfPresent(Int64.self, forKey: .expiresDateMs)
        webOrderLineItemId = try c.id(.webOrderLineItemId)
        cancellationDateMs = try c.decodeIfPresent(Int64.self, forKey: .cancellationDateMs)
        isTrialPeriod = try c.decodeIfPresent(Bool.self, forKey: .isTrialPeriod)
        isInIntroOfferPeriod = try c.decodeIfPresent(Bool.self, forKey: .isInIntroOfferPeriod)
        unknownAttributes = try c.attributes(.unknownAttributes)
    }
}

extension KeyedDecodingContainer {
    /// A 64-bit id, which the wire writes as a decimal string.
    fileprivate func id(_ key: Key) throws -> Int64? {
        guard let text = try decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let value = Int64(text) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "not a 64-bit id")
        }
        return value
    }

    /// Bytes, which the wire writes as padded standard base64.
    fileprivate func bytes(_ key: Key) throws -> [UInt8]? {
        guard let text = try decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let data = Data(base64Encoded: text) else {
            throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "not base64")
        }
        return [UInt8](data)
    }

    /// Unknown attributes: keyed by decimal type, each a list of base64 values
    /// in receipt order.
    fileprivate func attributes(_ key: Key) throws -> [Int: [[UInt8]]] {
        guard let wire = try decodeIfPresent([String: [String]].self, forKey: key) else { return [:] }
        var out: [Int: [[UInt8]]] = [:]
        for (type, values) in wire {
            guard let number = Int(type), let decoded = Optional(values.compactMap { Data(base64Encoded: $0).map { [UInt8]($0) } }),
                decoded.count == values.count
            else {
                throw DecodingError.dataCorruptedError(forKey: key, in: self, debugDescription: "not an attribute map")
            }
            out[number] = decoded
        }
        return out
    }
}
