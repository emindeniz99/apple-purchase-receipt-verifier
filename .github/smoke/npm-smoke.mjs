// Smoke-tests the package as published to npm, by name, from a directory that
// is not the repository. Run it after installing the published version:
//
//   cd "$(mktemp -d)" && npm init -y && npm i apple-purchase-receipt-verifier@0.7.0
//   cp <repo>/fixtures/public-receipts/receipt-sandbox-g5.b64 .
//   node <repo>/.github/smoke/npm-smoke.mjs
//
// The import is by package name, not by path, so a broken "exports" map or a
// missing entry point fails here rather than in a user's project. 0.1.1 and
// 0.2.0 shipped with no dist/ at all and this file is what would have caught it.
import { readFileSync } from 'node:fs'
import { Reason, createConfig, createVerifier } from 'apple-purchase-receipt-verifier'

const receiptB64 = readFileSync('receipt-sandbox-g5.b64', 'ascii').trim()

// Apple's three roots are compiled into aprv.wasm, so the defaults name no
// roots of their own (null means the module's); a package that lost the
// module or its glue fails below, on the genuine receipt.
const config = createConfig()
if (config.roots !== null) {
  throw new Error(`expected the module's built-in roots (null), got ${config.roots}`)
}
const verifier = createVerifier(config)

// A real Apple-signed receipt against the real pinned root: exercises the
// bundled certs, the DER reader, the chain build and the signature check.
const result = verifier.verifyReceipt(receiptB64)
if (!result.verified) {
  throw new Error(`verification failed: ${result.failure.reason}: ${result.failure.message}`)
}
const receipt = result.payload
if (receipt.receiptType !== 'ProductionSandbox') {
  throw new Error(`receiptType was ${receipt.receiptType}, expected ProductionSandbox`)
}
if (receipt.bundleId !== 'dev.bonzer.weeka.app') {
  throw new Error(`bundleId was ${receipt.bundleId}`)
}

// And the negative direction, so a verifier that accepted everything would fail
// here too: the same receipt with one bit flipped in its signature, the byte
// 128 from the end of the DER (BENCHMARKS.md).
const der = Buffer.from(receiptB64, 'base64')
der[der.length - 128] ^= 0x01
const tampered = verifier.verifyReceipt(der.toString('base64'))
if (tampered.verified || tampered.failure.reason !== Reason.INVALID_SIGNATURE) {
  throw new Error(`a tampered signature was not rejected as INVALID_SIGNATURE: ${
    tampered.verified ? 'verified' : tampered.failure.reason}`)
}

console.log(`npm: published package verified a genuine Apple receipt (${receipt.bundleId}, `
  + `${receipt.inApp.length} purchases) and rejected a tampered signature`)
