# Cloudflare workerd smoke, run by `node runtime-smoke/run-workerd.mjs`
# after `npm run build`. Module names mirror the package layout so the
# relative imports inside dist/ resolve unchanged. "#aprv-load" is the
# package.json "imports" entry resolved by hand for the workerd condition,
# as wrangler's bundler does: the loader that imports the core modules
# statically. workerd names it relative to its importer, dist/engine.js,
# and resolves the loader's own "../generated/" imports from there, which
# is why the core modules are named generated/ here. No compatibility
# flags: the package needs no Node API here.
# Embed paths are relative to this file.
using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [ (name = "main", worker = .worker) ],
);

const worker :Workerd.Worker = (
  modules = [
    (name = "runtime-smoke/worker.mjs", esModule = embed "worker.mjs"),
    (name = "runtime-smoke/smoke.mjs", esModule = embed "smoke.mjs"),
    (name = "dist/index.js", esModule = embed "../dist/index.js"),
    (name = "dist/web/index.js", esModule = embed "../dist/web/index.js"),
    (name = "dist/config.js", esModule = embed "../dist/config.js"),
    (name = "dist/engine.js", esModule = embed "../dist/engine.js"),
    (name = "dist/environment.js", esModule = embed "../dist/environment.js"),
    (name = "dist/errors.js", esModule = embed "../dist/errors.js"),
    (name = "dist/payload.js", esModule = embed "../dist/payload.js"),
    (name = "dist/verifier.js", esModule = embed "../dist/verifier.js"),
    (name = "dist/generated/aprv.js", esModule = embed "../dist/generated/aprv.js"),
    (name = "dist/#aprv-load", esModule = embed "../dist/load/static.js"),
    (name = "generated/aprv.core.wasm", wasm = embed "../dist/generated/aprv.core.wasm"),
    (name = "generated/aprv.core2.wasm", wasm = embed "../dist/generated/aprv.core2.wasm"),
    (name = "generated/aprv.core3.wasm", wasm = embed "../dist/generated/aprv.core3.wasm"),
    (name = "fixtures/receipt-sandbox-g5.b64", text = embed "../../fixtures/public-receipts/receipt-sandbox-g5.b64"),
    (name = "fixtures/jws-root.der", data = embed "../../fixtures/generated/jws-root.der"),
    (name = "fixtures/transaction.jws", text = embed "../../fixtures/generated/transaction.jws"),
  ],
  compatibilityDate = "2026-08-01",
);
