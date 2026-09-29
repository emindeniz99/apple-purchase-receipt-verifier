// Runtime smoke: the same checks on every JavaScript runtime the package
// claims (Node, Bun, Deno, workerd, the Vercel Edge runtime, browsers). No
// filesystem access here: the runner passes the fixtures in, and passes the
// package's entry module in as `api` (the default one or /web; both are
// awaited, so one script serves both).
//
// The genuine receipt is checked through the endpoint, whose answer is
// Apple's own JSON; the verifyReceipt and verifySignedData checks run in
// full when the loaded module answers the 0.7 wire (the release module) and
// report themselves skipped when it does not (the 0.6-core stand-in the
// package carries until the Rust core lands).

/**
 * @param {object} api the package entry point
 * @param {{ sandboxReceiptB64: string, jwsRootDer: Uint8Array,
 *           transactionJws: string }} fx
 * @returns {Promise<string[]>} one line per check
 */
export async function run(api, fx) {
  const out = [];
  const g5 = fx.sandboxReceiptB64.trim();
  const request = JSON.stringify({ 'receipt-data': g5 });

  const apple = api.createVerifier(await api.defaultConfig());
  const sandbox = JSON.parse(await apple.verifyReceiptEndpoint(api.Environment.SANDBOX, request));
  if (sandbox.status !== 0 || sandbox.receipt?.bundle_id !== 'dev.bonzer.weeka.app') {
    throw new Error(`genuine receipt on the sandbox endpoint: status ${sandbox.status}`);
  }
  out.push('genuine sandbox receipt verifies against the pinned Apple roots (endpoint status 0)');
  const production = JSON.parse(
    await apple.verifyReceiptEndpoint(api.Environment.PRODUCTION, request),
  );
  if (production.status !== 21007) {
    throw new Error(`genuine sandbox receipt on the production endpoint: ${production.status}`);
  }
  out.push('the same receipt on the production endpoint is 21007');

  const wire07 = (await apple.verifyReceipt('')).failure?.reason === 'MALFORMED';
  if (!wire07) {
    out.push('SKIP verifyReceipt and verifySignedData: the module does not answer the 0.7 wire');
    return out;
  }
  const receipt = await apple.verifyReceipt(g5);
  if (!receipt.verified || receipt.payload.bundleId !== 'dev.bonzer.weeka.app') {
    throw new Error(`verifyReceipt: ${receipt.failure?.reason}`);
  }
  out.push('verifyReceipt returns the genuine receipt payload');

  const jws = api.createVerifier(await api.createConfig({ roots: [fx.jwsRootDer] }));
  const tx = await jws.verifySignedData(fx.transactionJws.trim());
  if (!tx.verified || JSON.parse(tx.payload.json).transactionId !== '2000000000000001') {
    throw new Error(`verifySignedData: ${tx.failure?.reason}`);
  }
  out.push('verifySignedData returns the shared transaction fixture');
  return out;
}
