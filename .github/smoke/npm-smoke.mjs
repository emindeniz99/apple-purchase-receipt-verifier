// Smoke-tests the package as published to npm, by name, from a directory that
// is not the repository. Run it after installing the published version:
//
//   cd "$(mktemp -d)" && npm init -y && npm i apple-purchase-receipt-verifier@0.2.1
//   cp <repo>/fixtures/public-receipts/receipt-sandbox-g5.b64 .
//   node <repo>/.github/smoke/npm-smoke.mjs
//
// The import is by package name, not by path, so a broken "exports" map or a
// missing entry point fails here rather than in a user's project. 0.1.1 and
// 0.2.0 shipped with no dist/ at all and this file is what would have caught it.
import { readFileSync } from 'node:fs'
import { ReceiptVerifier, appleReceiptRoots } from 'apple-purchase-receipt-verifier'

const receiptB64 = readFileSync('receipt-sandbox-g5.b64', 'ascii').trim()
const verifier = new ReceiptVerifier({
  trustedRoots: appleReceiptRoots(),
  bundleId: 'dev.bonzer.weeka.app',
})

// A real Apple-signed receipt against the real pinned root: exercises the
// bundled certs, the DER reader, the chain build and the signature check.
const receipt = verifier.verify(receiptB64)
if (receipt.receiptType !== 'ProductionSandbox') {
  throw new Error(`receiptType was ${receipt.receiptType}, expected ProductionSandbox`)
}
if (receipt.bundleId !== 'dev.bonzer.weeka.app') {
  throw new Error(`bundleId was ${receipt.bundleId}`)
}

// And the negative direction, so a verifier that accepted everything would fail
// here too.
let rejected = false
try {
  new ReceiptVerifier({ trustedRoots: appleReceiptRoots(), bundleId: 'com.other.app' })
    .verify(receiptB64)
} catch (e) {
  rejected = e.reason === 'WRONG_BUNDLE_ID'
}
if (!rejected) {
  throw new Error('a receipt for another bundle id was not rejected')
}

console.log(`npm: published package verified a genuine Apple receipt (${receipt.bundleId}, `
  + `${receipt.inAppPurchases.length} purchases) and rejected a foreign bundle id`)
