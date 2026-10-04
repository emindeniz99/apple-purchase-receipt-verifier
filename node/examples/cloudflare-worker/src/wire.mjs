// aprv-server's envelope around what the package returns. The package
// hands back objects for verifyReceipt and verifySignedData, not the
// module's text, so the Worker and the demo page both put the envelope
// back with this one function. The receipt payload is the package's own
// `toJson()`; nothing here reads a receipt.
const receiptWire = (payload) => payload.toJson();
const jwsWire = (payload) => JSON.stringify(payload.json);

function resultJson(result, payloadWire) {
  if (result.verified) {
    const environment = JSON.stringify(result.payload.environment ?? null);
    return `{"verified":true,"payload":${payloadWire(result.payload)},"environment":${environment}}`;
  }
  const { reason, message } = result.failure;
  return JSON.stringify({ verified: false, reason, message });
}

/**
 * The four operations by route, each `(verifier, body) => Promise<string>`
 * over a `/web` Verifier. `Environment` is the package's.
 */
export function operations(Environment) {
  return new Map([
    ['/v1/receipt/verify', async (v, body) => resultJson(await v.verifyReceipt(body), receiptWire)],
    [
      '/v1/signed-data/verify',
      async (v, body) => resultJson(await v.verifySignedData(body), jwsWire),
    ],
    [
      '/v1/verify-receipt/production',
      (v, body) => v.verifyReceiptEndpoint(Environment.PRODUCTION, body),
    ],
    ['/v1/verify-receipt/sandbox', (v, body) => v.verifyReceiptEndpoint(Environment.SANDBOX, body)],
  ]);
}
