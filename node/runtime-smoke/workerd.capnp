# Cloudflare Workers smoke, run by `npx workerd test runtime-smoke/workerd.capnp`
# from node/ after `npm run build`. Module names mirror the repo layout so
# the relative imports inside dist/ resolve unchanged. Embed paths are
# relative to this file.
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [ (name = "main", worker = .worker) ],
);

const worker :Workerd.Worker = (
  modules = [
    (name = "runtime-smoke/worker.mjs", esModule = embed "worker.mjs"),
    (name = "runtime-smoke/smoke.mjs", esModule = embed "smoke.mjs"),
    (name = "dist/index.js", esModule = embed "../dist/index.js"),
    (name = "dist/apple-date.js", esModule = embed "../dist/apple-date.js"),
    (name = "dist/bytes.js", esModule = embed "../dist/bytes.js"),
    (name = "dist/call-clock.js", esModule = embed "../dist/call-clock.js"),
    (name = "dist/chain.js", esModule = embed "../dist/chain.js"),
    (name = "dist/cms.js", esModule = embed "../dist/cms.js"),
    (name = "dist/config.js", esModule = embed "../dist/config.js"),
    (name = "dist/crypto.js", esModule = embed "../dist/crypto.js"),
    (name = "dist/der.js", esModule = embed "../dist/der.js"),
    (name = "dist/environment.js", esModule = embed "../dist/environment.js"),
    (name = "dist/errors.js", esModule = embed "../dist/errors.js"),
    (name = "dist/json.js", esModule = embed "../dist/json.js"),
    (name = "dist/jws.js", esModule = embed "../dist/jws.js"),
    (name = "dist/limits.js", esModule = embed "../dist/limits.js"),
    (name = "dist/pem.js", esModule = embed "../dist/pem.js"),
    (name = "dist/receipt-payload.js", esModule = embed "../dist/receipt-payload.js"),
    (name = "dist/receipt.js", esModule = embed "../dist/receipt.js"),
    (name = "dist/roots-data.js", esModule = embed "../dist/roots-data.js"),
    (name = "dist/safe-text.js", esModule = embed "../dist/safe-text.js"),
    (name = "dist/strict-utf8.js", esModule = embed "../dist/strict-utf8.js"),
    (name = "dist/verifier.js", esModule = embed "../dist/verifier.js"),
    (name = "dist/verify-receipt-endpoint.js", esModule = embed "../dist/verify-receipt-endpoint.js"),
    (name = "dist/x509.js", esModule = embed "../dist/x509.js"),
    (name = "fixtures/AppleIncRootCertificate.cer", data = embed "../certs/AppleIncRootCertificate.cer"),
    (name = "fixtures/receipt-sandbox-g5.b64", text = embed "../../fixtures/public-receipts/receipt-sandbox-g5.b64"),
    (name = "fixtures/jws-root.der", data = embed "../../fixtures/generated/jws-root.der"),
    (name = "fixtures/transaction.jws", text = embed "../../fixtures/generated/transaction.jws"),
    (name = "fixtures/receipt-foreign.der", data = embed "../../fixtures/generated/receipt-foreign.der"),
  ],
  # nodejs_compat supplies node:crypto (createPublicKey, verify, createHash)
  # and node:buffer. dist/config.js also imports node:crypto directly, and
  # some dist modules use Buffer as a convenience — nodejs_compat provides
  # a compatible global. An older compatibility date fails at import time.
  compatibilityDate = "2026-08-01",
  compatibilityFlags = ["nodejs_compat"],
);
