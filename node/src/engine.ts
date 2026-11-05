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
 * - the ABI check: the module must export the `@0.2.0` operations this
 *   package calls and import exactly `random-get`, or `createVerifier`
 *   fails naming what the module has;
 * - `init` once per instance, with the roots and revocation settings of the
 *   caller's `Config`, and what its answer states: `max_input_bytes`, the
 *   most bytes of one input the module needs, which the instance's calls
 *   cut their input to, and the revocation state the `Verifier` reports;
 * - dropping an instance after any failure inside it. A trapped component
 *   instance refuses every later call ("cannot enter component instance"),
 *   so the next call instantiates a fresh one and runs `init` again.
 */
import { getCoreModule } from '#aprv-load';
import { instantiate } from './generated/aprv.js';

/** The WIT interface this package binds; its version is the ABI version. */
export const ABI_INTERFACE = 'aprv:verifier/verify@0.2.0';
const HOST_INTERFACE = 'aprv:verifier/host@0.2.0';
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

/**
 * `init` refused the configuration: a root or an issuer that is not a
 * certificate, a revocation list or `distrust` entry the module refuses.
 */
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
 * it must export the four `@0.2.0` operations and import exactly
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

/** The revocation members of `init`'s configuration: base64 of each list and issuer, and the distrust entries. */
export interface InitRevocation {
  readonly lists?: readonly string[];
  readonly issuers?: readonly string[];
  readonly distrust?: readonly { readonly issuer: string; readonly serial: string }[];
}

/**
 * `init`'s configuration: the roots' bytes (DER or PEM) as base64, or no
 * `roots` member for Apple's roots, and each revocation setting that is
 * not empty. With neither it is `{}`.
 */
export function initConfig(
  rootsBase64?: readonly string[],
  revocation: InitRevocation = {},
): Uint8Array {
  const config: Record<string, unknown> = {};
  if (rootsBase64 !== undefined) {
    config['roots'] = rootsBase64;
  }
  const { lists = [], issuers = [], distrust = [] } = revocation;
  if (lists.length > 0) {
    config['revocation_lists'] = lists;
  }
  if (issuers.length > 0) {
    config['revocation_issuers'] = issuers;
  }
  if (distrust.length > 0) {
    // Exactly the two members the module reads, whatever else the object holds.
    config['distrust'] = distrust.map(({ issuer, serial }) => ({ issuer, serial }));
  }
  return utf8.encode(JSON.stringify(config));
}

/** What an accepting `init` answer states. */
export interface InitAnswer {
  /** The most bytes of one input the module needs. */
  readonly maxInputBytes: number;
  /** The URLs of the revocation lists the verifier would use, in the module's order. */
  readonly revocationUrls: readonly string[];
  /** The earliest `nextUpdate` of the lists held, epoch milliseconds, or null. */
  readonly revocationValidUntilMs: number | null;
}

/**
 * Reads `init`'s answer: `{"ok":true,"max_input_bytes":N,
 * "revocation_urls":[...],"revocation_valid_until_ms":N|null}`, with a
 * positive integer N. An accepting answer without all three comes from a
 * module of another version and is no answer.
 */
export function initAnswer(text: string): InitAnswer {
  let answer: unknown;
  try {
    answer = JSON.parse(text);
  } catch {
    throw new Error('init answered something that is not JSON');
  }
  if (answer !== null && typeof answer === 'object') {
    const {
      ok,
      message,
      max_input_bytes: maxInputBytes,
      revocation_urls: urls,
      revocation_valid_until_ms: validUntil,
    } = answer as Record<string, unknown>;
    if (
      ok === true &&
      Number.isSafeInteger(maxInputBytes) &&
      (maxInputBytes as number) > 0 &&
      Array.isArray(urls) &&
      urls.every((url) => typeof url === 'string') &&
      (validUntil === null || Number.isSafeInteger(validUntil))
    ) {
      return Object.freeze({
        maxInputBytes: maxInputBytes as number,
        revocationUrls: Object.freeze([...(urls as string[])]),
        revocationValidUntilMs: validUntil as number | null,
      });
    }
    if (ok === false && typeof message === 'string') {
      throw new InitRefusedError(message, text);
    }
  }
  throw new Error(
    'init answered neither {"ok":true,"max_input_bytes":N,"revocation_urls":[...],' +
      '"revocation_valid_until_ms":N|null} nor {"ok":false,"message":...}',
  );
}

/** An initialised instance and what its `init` stated. */
interface Instance {
  readonly bindings: Bindings;
  readonly answer: InitAnswer;
}

function freshInstance(config: Uint8Array): Instance {
  checkAbi();
  const bindings = instantiate(getCoreModule, IMPORTS).verify;
  return { bindings, answer: initAnswer(bindings.init(config)) };
}

/**
 * One instance and the `init` configuration to rebuild it with. JavaScript
 * runs one call at a time, so one instance serves every call of its
 * `Verifier`.
 */
export class Slot {
  #config: Uint8Array;
  #instance: Instance | null;
  /**
   * The first instance's `init` answer. A later instance gets the same
   * configuration, so its answer is not read again for the revocation state.
   */
  readonly initAnswer: InitAnswer;

  /**
   * Instantiates and runs `init` now, so a refused root or revocation
   * setting fails the caller's `createVerifier`.
   */
  constructor(config: Uint8Array) {
    this.#config = config;
    this.#instance = freshInstance(config);
    this.initAnswer = this.#instance.answer;
  }

  /**
   * Runs `op` on the instance, creating one first if the last was dropped;
   * `op` gets the `max_input_bytes` that instance's `init` stated. Anything
   * thrown (a trap, a refused instance, an answer `read` cannot read) drops
   * the instance and is rethrown for the caller to report.
   */
  call<T>(op: (bindings: Bindings, maxInputBytes: number) => string, read: (text: string) => T): T {
    try {
      this.#instance ??= freshInstance(this.#config);
      return read(op(this.#instance.bindings, this.#instance.answer.maxInputBytes));
    } catch (error) {
      this.#instance = null;
      throw error;
    }
  }
}
