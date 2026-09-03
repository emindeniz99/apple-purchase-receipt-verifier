# Cloudflare Workers smoke for the WEB entry point, run by
# `node runtime-smoke/run-web-workerd.mjs` from node/ after `npm run build`.
# Module names mirror the repo layout so the relative imports inside dist/
# resolve unchanged. Embed paths are relative to this file.
#
# The point of this config is what it does NOT have: no compatibilityFlags
# at all. dist/web/ imports nothing from node:*, so nodejs_compat is not
# needed and the compatibility date is free to be anything workerd accepts.
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [ (name = "main", worker = .worker) ],
);

const worker :Workerd.Worker = (
  modules = [
    (name = "runtime-smoke/web-worker.mjs", esModule = embed "web-worker.mjs"),
    (name = "runtime-smoke/web-smoke.mjs", esModule = embed "web-smoke.mjs"),
    (name = "dist/web/index.js", esModule = embed "../dist/web/index.js"),
    (name = "dist/web/chain.js", esModule = embed "../dist/web/chain.js"),
    (name = "dist/web/crypto.js", esModule = embed "../dist/web/crypto.js"),
    (name = "dist/web/jws.js", esModule = embed "../dist/web/jws.js"),
    (name = "dist/web/receipt.js", esModule = embed "../dist/web/receipt.js"),
    (name = "dist/web/roots.js", esModule = embed "../dist/web/roots.js"),
    (name = "dist/bytes.js", esModule = embed "../dist/bytes.js"),
    (name = "dist/cms.js", esModule = embed "../dist/cms.js"),
    (name = "dist/der.js", esModule = embed "../dist/der.js"),
    (name = "dist/errors.js", esModule = embed "../dist/errors.js"),
    (name = "dist/jws-claims.js", esModule = embed "../dist/jws-claims.js"),
    (name = "dist/receipt-payload.js", esModule = embed "../dist/receipt-payload.js"),
    (name = "dist/roots-data.js", esModule = embed "../dist/roots-data.js"),
    (name = "dist/x509.js", esModule = embed "../dist/x509.js"),
    (name = "fixtures/AppleIncRootCertificate.cer", data = embed "../certs/AppleIncRootCertificate.cer"),
    (name = "fixtures/receipt-sandbox-g5.b64", text = embed "../../fixtures/public-receipts/receipt-sandbox-g5.b64"),
    (name = "fixtures/receipt-sandbox-legacy.b64", text = embed "../../fixtures/public-receipts/receipt-sandbox-legacy.b64"),
    (name = "fixtures/jws-root.der", data = embed "../../fixtures/generated/jws-root.der"),
    (name = "fixtures/transaction.jws", text = embed "../../fixtures/generated/transaction.jws"),
    (name = "fixtures/receipt-foreign.der", data = embed "../../fixtures/generated/receipt-foreign.der"),
  ],
  compatibilityDate = "2024-09-23",
);
