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
    (name = "dist/chain.js", esModule = embed "../dist/chain.js"),
    (name = "dist/der.js", esModule = embed "../dist/der.js"),
    (name = "dist/errors.js", esModule = embed "../dist/errors.js"),
    (name = "dist/jws.js", esModule = embed "../dist/jws.js"),
    (name = "dist/receipt.js", esModule = embed "../dist/receipt.js"),
    (name = "dist/roots.js", esModule = embed "../dist/roots.js"),
    (name = "dist/verify-receipt-endpoint.js", esModule = embed "../dist/verify-receipt-endpoint.js"),
    (name = "fixtures/AppleIncRootCertificate.cer", data = embed "../certs/AppleIncRootCertificate.cer"),
    (name = "fixtures/receipt-sandbox-g5.b64", text = embed "../../fixtures/public-receipts/receipt-sandbox-g5.b64"),
    (name = "fixtures/jws-root.der", data = embed "../../fixtures/generated/jws-root.der"),
    (name = "fixtures/transaction.jws", text = embed "../../fixtures/generated/transaction.jws"),
    (name = "fixtures/receipt-foreign.der", data = embed "../../fixtures/generated/receipt-foreign.der"),
  ],
  # nodejs_compat supplies node:crypto (X509Certificate, verify, createHash)
  # and node:buffer. dist/roots.js also imports node:fs, which workerd only
  # resolves from compatibility dates in late 2025 onward — an older date
  # fails at import time with `No such module "node:fs"`.
  compatibilityDate = "2026-08-01",
  compatibilityFlags = ["nodejs_compat"],
);
