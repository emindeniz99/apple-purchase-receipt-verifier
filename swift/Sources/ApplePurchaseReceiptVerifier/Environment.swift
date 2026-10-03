/// Which of Apple's two `verifyReceipt` URLs a call imitates, and the
/// environment a verified payload states (``ReceiptPayload/environment``,
/// ``JsonPayload/environment``).
public enum Environment: String, Sendable {
    case production = "Production"
    case sandbox = "Sandbox"
}
