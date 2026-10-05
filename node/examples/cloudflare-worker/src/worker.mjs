// aprv-server's wire contract (rust/server/README.md, "The wire contract")
// on Cloudflare Workers, over the npm package.
//
// The Worker reads the clock, moves the body into the package and returns
// its answer. It parses no receipt, checks no signature and decides no
// trust. It never logs a body, a receipt or a payload: a receipt carries a
// user's purchase history.
import { createConfig, createVerifier, Environment } from 'apple-purchase-receipt-verifier/web';
import { operations } from './wire.mjs';
// A path, not the package's name: its `exports` does not list package.json.
import pkg from '../node_modules/apple-purchase-receipt-verifier/package.json';

// The module states this at `init`: one over its largest cap. The package
// cuts an input there itself but does not report the number, so it is
// repeated here, only to stop reading a body and to choose 413 over 200.
// The refusal in the 413's body is still the module's own.
const MAX_INPUT_BYTES = 3_145_729;

const PROBLEM_TYPE =
  'https://github.com/emindeniz99/apple-purchase-receipt-verifier/blob/main/rust/server/README.md#';

const POST_ROUTES = operations(Environment);
const GET_ROUTES = new Set(['/v1/info', '/healthz', '/readyz']);

// One Verifier per isolate, built by the first request and reused. A
// Verifier's clock belongs to its Config, so the clock reads the time of
// the request being served: X-Aprv-Now-Ms when the request has one. Every
// verify call reads the clock before it first yields, so no other request
// can change `requestNowMs` in between.
let requestNowMs = null;
let verifierPromise = null;

function verifier() {
  // A failed start is forgotten, so the next request (or /readyz) tries
  // again instead of failing for the rest of the isolate's life.
  verifierPromise ??= createConfig({ clock: () => requestNowMs ?? Date.now() })
    .then(createVerifier)
    .catch((error) => {
      verifierPromise = null;
      throw error;
    });
  return verifierPromise;
}

function json(status, body, contentType = 'application/json') {
  return new Response(body, { status, headers: { 'content-type': contentType } });
}

function problem(status, code, title, detail, anchor) {
  const body = { type: PROBLEM_TYPE + anchor, title, status, detail, code };
  return json(status, JSON.stringify(body), 'application/problem+json');
}

/** X-Aprv-Now-Ms: `null` without the header, `undefined` when it is not usable. */
function nowHeader(request) {
  const value = request.headers.get('x-aprv-now-ms');
  if (value === null) {
    return null;
  }
  // The contract says u64; the package's clock is a JavaScript number.
  const ms = /^\d{1,20}$/.test(value) ? Number(value) : NaN;
  return Number.isSafeInteger(ms) ? ms : undefined;
}

/**
 * The body as text and whether it reached MAX_INPUT_BYTES. No more than
 * that many bytes are kept; the rest of the stream is cancelled.
 */
async function readBody(request) {
  const bytes = new Uint8Array(MAX_INPUT_BYTES);
  let length = 0;
  if (request.body !== null) {
    const reader = request.body.getReader();
    while (length < MAX_INPUT_BYTES) {
      // oxlint-disable-next-line no-await-in-loop -- a stream is read in order
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      const chunk = value.subarray(0, MAX_INPUT_BYTES - length);
      bytes.set(chunk, length);
      length += chunk.length;
    }
    if (length === MAX_INPUT_BYTES) {
      await reader.cancel();
    }
  }
  return {
    text: new TextDecoder().decode(bytes.subarray(0, length)),
    oversized: length === MAX_INPUT_BYTES,
  };
}

async function verify(request, operation) {
  const nowMs = nowHeader(request);
  if (nowMs === undefined) {
    return problem(
      400,
      'BAD_REQUEST',
      'Bad Request',
      'X-Aprv-Now-Ms must be decimal epoch milliseconds, at most 9007199254740991',
      'bad-request',
    );
  }
  let body;
  try {
    body = await readBody(request);
  } catch {
    return problem(400, 'BAD_REQUEST', 'Bad Request', 'the body could not be read', 'bad-request');
  }
  let v;
  try {
    v = await verifier();
  } catch {
    return problem(
      500,
      'INTERNAL_ERROR',
      'Internal Server Error',
      'the verifier could not be created',
      'internal-error',
    );
  }
  let answer;
  try {
    requestNowMs = nowMs;
    const pending = operation(v, body.text);
    requestNowMs = null;
    answer = await pending;
  } catch {
    requestNowMs = null;
    return problem(
      500,
      'INTERNAL_ERROR',
      'Internal Server Error',
      'the verifier threw instead of answering',
      'internal-error',
    );
  }
  return json(body.oversized ? 413 : 200, answer);
}

async function route(request, env) {
  const { pathname } = new URL(request.url);
  const post = POST_ROUTES.get(pathname);
  if (post === undefined && !GET_ROUTES.has(pathname)) {
    return problem(404, 'NOT_FOUND', 'Not Found', 'no such route', 'not-found');
  }
  if (request.method !== (post === undefined ? 'GET' : 'POST')) {
    const response = problem(
      405,
      'METHOD_NOT_ALLOWED',
      'Method Not Allowed',
      'the route exists for another method',
      'method-not-allowed',
    );
    response.headers.set('allow', post === undefined ? 'GET' : 'POST');
    return response;
  }
  if (pathname === '/healthz') {
    return new Response('ok');
  }
  if (pathname === '/readyz') {
    await verifier();
    return new Response('ready');
  }
  const key = request.headers.get('cf-connecting-ip') ?? 'unknown';
  const { success } = await env.RATE_LIMITER.limit({ key });
  if (!success) {
    // Not an aprv-server problem, so no `type` link into its README.
    const body = {
      title: 'Too Many Requests',
      status: 429,
      detail: 'rate limit exceeded for this address; retry in a minute',
      code: 'RATE_LIMITED',
    };
    const response = json(429, JSON.stringify(body), 'application/problem+json');
    response.headers.set('retry-after', '60');
    return response;
  }
  if (pathname === '/v1/info') {
    const info = {
      package: pkg.name,
      version: pkg.version,
      engine: 'cloudflare-workers',
      roots: 'the three Apple roots compiled into aprv.wasm',
    };
    return json(200, JSON.stringify(info));
  }
  return verify(request, post);
}

export default {
  async fetch(request, env) {
    let response;
    try {
      response = await route(request, env);
    } catch {
      response = problem(
        500,
        'INTERNAL_ERROR',
        'Internal Server Error',
        'the request could not be served',
        'internal-error',
      );
    }
    // Not part of aprv-server's contract: which package release answered.
    response.headers.set('x-aprv-version', pkg.version);
    const { pathname } = new URL(request.url);
    console.log(`${request.method} ${pathname} ${response.status}`);
    return response;
  },
};
