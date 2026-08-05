import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';

/**
 * Loads the Apple root certificates bundled with this package (copies of
 * the public roots from https://www.apple.com/certificateauthority/).
 * Production trust anchors; tests use the shared fixture PKI instead.
 */
function load(name) {
  return new X509Certificate(readFileSync(fileURLToPath(new URL(`../certs/${name}`, import.meta.url))));
}

/** Apple Root CA - G3 — anchors StoreKit 2 / App Store Server JWS chains. */
export function appleJwsRoots() {
  return [load('AppleRootCA-G3.cer')];
}

/** Apple Inc. Root CA — anchors legacy PKCS#7 app-receipt chains. */
export function appleReceiptRoots() {
  return [load('AppleIncRootCertificate.cer')];
}
