/**
 * aprv.wasm through jco's generated bindings: one compiled module per
 * module load, and a {@link Slot} per `Verifier` that holds one instance.
 *
 * This file moves bytes and strings between JavaScript and the module and
 * decides nothing about a receipt or a JWS. What it does own:
 *
 * - the one import the module has, `random-get`, answered from
 *   `crypto.getRandomValues` in 65,536-byte chunks (the most one call of
 *   that function may fill); any other import the bindings ask for is
 *   refused;
 * - the ABI check: the module must export the `@0.1.0` operations this
 *   package calls and import exactly `random-get`, or `createVerifier`
 *   fails naming what the module has;
 * - `init` once per instance, with the roots of the caller's `Config`;
 * - dropping an instance after any failure inside it. A trapped component
 *   instance refuses every later call ("cannot enter component instance"),
 *   so the next call instantiates a fresh one and runs `init` again.
 */
import { getCoreModule } from '#aprv-load';
import { instantiate } from './generated/aprv.js';

/** The WIT interface this package binds; its version is the ABI version. */
export const ABI_INTERFACE = 'aprv:verifier/verify@0.1.0';
const HOST_INTERFACE = 'aprv:verifier/host@0.1.0';
const OPERATIONS = ['init', 'verify-receipt', 'verify-signed-data', 'verify-receipt-endpoint'];
const RANDOM_CHUNK = 65536;

/** The four operations of the WIT interface, as jco binds them. */
export type Bindings = ReturnType<typeof instantiate>['verify'];

/** The module is not the one this package was built for. Thrown at `createVerifier`. */
export class AbiMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AbiMismatchError';
  }
}

/** `init` refused the configuration: a root that is not a certificate. */
export class InitRefusedError extends Error {
  /** `init`'s answer, exactly as the module wrote it. */
  readonly answer: string;

  constructor(message: string, answer: string) {
    super(message);
    this.name = 'InitRefusedError';
    this.answer = answer;
  }
}

/** The `random-get` import: `len` bytes from `crypto.getRandomValues`, 64 KiB at a time. */
export function randomGet(len: number): Uint8Array {
  const out = new Uint8Array(len);
  for (let offset = 0; offset < len; offset += RANDOM_CHUNK) {
    crypto.getRandomValues(out.subarray(offset, Math.min(offset + RANDOM_CHUNK, len)));
  }
  return out;
}

const HOST = Object.freeze({ randomGet });

// jco's glue reads the host interface under its unversioned name; the
// versioned one is what its type declarations name. Both give the same
// object, and any other name is refused rather than answered.
const IMPORTS = new Proxy(Object.freeze({}), {
  get(_target, key): typeof HOST {
    if (key === 'aprv:verifier/host' || key === HOST_INTERFACE) {
      return HOST;
    }
    throw new AbiMismatchError(
      `aprv.wasm asked for the import ${String(key)}; the only import provided is ${HOST_INTERFACE} random-get`,
    );
  },
}) as unknown as Parameters<typeof instantiate>[1];

/**
 * Why `core` is not the module this package binds, or `null` when it is:
 * it must export the four `@0.1.0` operations and import exactly
 * `random-get`.
 */
export function abiProblem(core: WebAssembly.Module): string | null {
  const exports = WebAssembly.Module.exports(core).map((e) => e.name);
  const missing = OPERATIONS.map((op) => `${ABI_INTERFACE}#${op}`).filter(
    (name) => !exports.includes(name),
  );
  if (missing.length > 0) {
    return (
      `aprv.wasm does not implement ${ABI_INTERFACE}: missing ${missing.join(', ')}; ` +
      `the module exports ${exports.join(', ') || 'nothing'}`
    );
  }
  const imports = WebAssembly.Module.imports(core);
  const onlyRandomGet =
    imports.length === 1 &&
    imports[0]!.module === HOST_INTERFACE &&
    imports[0]!.name === 'random-get' &&
    imports[0]!.kind === 'function';
  if (!onlyRandomGet) {
    return (
      `aprv.wasm must import exactly ${HOST_INTERFACE} random-get; it imports ` +
      (imports.map((i) => `${i.module} ${i.name} (${i.kind})`).join(', ') || 'nothing')
    );
  }
  return null;
}

let abiChecked = false;

function checkAbi(): void {
  if (!abiChecked) {
    const problem = abiProblem(getCoreModule('aprv.core.wasm'));
    if (problem !== null) {
      throw new AbiMismatchError(problem);
    }
    abiChecked = true;
  }
}

const utf8 = new TextEncoder();

/** `init`'s configuration: the roots' bytes (DER or PEM) as base64, an empty list for Apple's roots. */
export function initConfig(rootsBase64: readonly string[]): Uint8Array {
  return utf8.encode(JSON.stringify({ roots: rootsBase64 }));
}

function initAnswer(text: string): void {
  let answer: unknown;
  try {
    answer = JSON.parse(text);
  } catch {
    throw new Error('init answered something that is not JSON');
  }
  if (answer !== null && typeof answer === 'object') {
    const { ok, message } = answer as { ok?: unknown; message?: unknown };
    if (ok === true) {
      return;
    }
    if (ok === false && typeof message === 'string') {
      throw new InitRefusedError(message, text);
    }
  }
  throw new Error('init answered neither {"ok":true} nor {"ok":false,"message":...}');
}

function freshInstance(config: Uint8Array): Bindings {
  checkAbi();
  const bindings = instantiate(getCoreModule, IMPORTS).verify;
  initAnswer(bindings.init(config));
  return bindings;
}

/**
 * One instance and the `init` configuration to rebuild it with. JavaScript
 * runs one call at a time, so one instance serves every call of its
 * `Verifier`.
 */
export class Slot {
  #config: Uint8Array;
  #bindings: Bindings | null;

  /** Instantiates and runs `init` now, so a refused root fails the caller's `createVerifier`. */
  constructor(config: Uint8Array) {
    this.#config = config;
    this.#bindings = freshInstance(config);
  }

  /**
   * Runs `op` on the instance, creating one first if the last was dropped.
   * Anything thrown (a trap, a refused instance, an answer `read` cannot
   * read) drops the instance and is rethrown for the caller to report.
   */
  call<T>(op: (bindings: Bindings) => string, read: (text: string) => T): T {
    try {
      this.#bindings ??= freshInstance(this.#config);
      return read(op(this.#bindings));
    } catch (error) {
      this.#bindings = null;
      throw error;
    }
  }
}
