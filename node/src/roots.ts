import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';

/**
 * Loads the Apple root certificates bundled with this package (copies of
 * the public roots from https://www.apple.com/certificateauthority/).
 * Production trust anchors; tests use the shared fixture PKI instead.
 *
 * Both sets contain all three published Apple roots. Apple deliberately
 * documents the JWS chain as ending in "an Apple root certificate" (not a
 * specific one) and its guidance is to trust every root on the PKI page,
 * so anchoring on a single root would break silently if Apple re-anchored
 * a path — see PLAN.md D15.
 */
function load(name: string): X509Certificate {
  return new X509Certificate(
    readFileSync(fileURLToPath(new URL(`../certs/${name}`, import.meta.url))));
}

function allRoots(): X509Certificate[] {
  return [
    load('AppleIncRootCertificate.cer'),
    load('AppleRootCA-G2.cer'),
    load('AppleRootCA-G3.cer'),
  ];
}

/**
 * Trust anchors for StoreKit 2 / App Store Server JWS chains.
 * Production chains currently end at Apple Root CA - G3.
 */
export function appleJwsRoots(): X509Certificate[] {
  return allRoots();
}

/**
 * Trust anchors for legacy PKCS#7 app-receipt chains.
 * Production chains currently end at the Apple Inc. Root CA.
 */
export function appleReceiptRoots(): X509Certificate[] {
  return allRoots();
}
