using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = ( services = [ (name = "main", worker = .worker) ] );
const worker :Workerd.Worker = (
  modules = [
    (name = "worker.mjs", esModule = embed "worker.mjs"),
    (name = "aprv_wasm.js", esModule = embed "aprv_wasm.js"),
    (name = "aprv_wasm_bg.wasm", wasm = embed "aprv_wasm_bg.wasm"),
    (name = "receipt-sandbox-g5.b64", text = embed "receipt-sandbox-g5.b64"),
    (name = "jws-root.der", data = embed "jws-root.der"),
    (name = "transaction.jws", text = embed "transaction.jws"),
  ],
  compatibilityDate = "2024-09-23",
);
