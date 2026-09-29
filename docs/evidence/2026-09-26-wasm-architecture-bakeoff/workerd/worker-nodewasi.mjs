// Spike only. Probes workerd's BUILT-IN WASI: node:wasi behind the
// enable_nodejs_wasi_module compatibility flag. Answers what happened.
import wasmModule from './aprv.wasm';
export default {
  async fetch() {
    const report = {};
    try {
      const { WASI } = await import('node:wasi');
      report.imported = typeof WASI;
      try {
        const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {} });
        report.constructed = true;
        const inst = new WebAssembly.Instance(wasmModule, wasi.getImportObject());
        wasi.initialize(inst);
        report.initialized = true;
      } catch (e) { report.error = String(e && e.message || e); }
    } catch (e) { report.importError = String(e && e.message || e); }
    return Response.json(report);
  },
};
