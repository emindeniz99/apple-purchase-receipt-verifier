# aprv-server's routes on Cloudflare Workers

A Worker that serves [aprv-server's wire contract](../../../rust/server/README.md#the-wire-contract)
over the `apple-purchase-receipt-verifier` npm package. It exists to show
that the package runs on Workers as a consumer installs it: from the
registry, bundled by wrangler, with no compatibility flag.

The Worker holds no verification logic. [`src/worker.mjs`](src/worker.mjs)
reads the clock, hands the request body to the package and returns its
answer. Every verdict is `aprv.wasm`'s.

## Run it

```bash
npm install
npx wrangler dev
```

```bash
# A public sandbox receipt from this repository's fixtures.
curl -s --data-binary @../../../fixtures/public-receipts/receipt-sandbox-g5.b64 \
  http://localhost:8787/v1/receipt/verify
# {"verified":true,"payload":{...},"environment":"Sandbox"}
```

Open http://localhost:8787/ for the demo page.

Deploy to your own account with `npx wrangler login`, then
`npx wrangler deploy`.

## The demo page

`/` serves [`public/index.html`](public/index.html), one HTML file with no
framework and no bundler. A switch chooses where the same input is
verified:

- **In this browser.** The page imports the package through an import map
  and verifies in the page. The input never leaves the device.
- **On the Worker.** The page posts the input to the routes below.
- **Both, compared.** The page does both and says whether the two answers
  are the same, leaving out the endpoint's `request_date`, which is each
  side's own clock.

Both sides run the same installed release and build their answer with the
same [`src/wire.mjs`](src/wire.mjs), so the two answers can be compared.
The page can load the public sandbox receipt from this repository's
fixtures and flip one character of the input to show a refusal.

wrangler's build step, [`scripts/copy-assets.mjs`](scripts/copy-assets.mjs),
copies the installed package's `dist/` to `public/vendor/` for the page;
that directory is not committed. Static files are served before the
Worker runs and are not rate limited.

## Routes

| Route | Body | Answer |
|---|---|---|
| `POST /v1/receipt/verify` | the `receipt-data` string | `{"verified":true,"payload":{...},"environment":...}` or `{"verified":false,"reason":"...","message":"..."}` |
| `POST /v1/signed-data/verify` | the compact JWS | the same, with the signed JSON as a string in `payload` |
| `POST /v1/verify-receipt/production` | a verifyReceipt request | Apple's endpoint response |
| `POST /v1/verify-receipt/sandbox` | a verifyReceipt request | Apple's endpoint response |
| `GET /v1/info` | | the package's name and version |
| `GET /healthz`, `GET /readyz` | | `ok`, `ready` |

A verification result is HTTP 200, verified or not. A body of 3,145,729
bytes or more is HTTP 413 with the module's own refusal as the body:
`TOO_LARGE`, or `{"status":21002}` at the endpoint routes. Any other
method on a route is 405 and any other path 404, as RFC 9457 problems
(`application/problem+json`) with aprv-server's `code`s.

`X-Aprv-Now-Ms` (decimal epoch milliseconds) sets the call's clock.
Without it the Worker's clock is used.

Every response carries `X-Aprv-Version`, the version of the npm package
that answered, so a caller knows which release it tested against.
aprv-server does not send this header.

## Where it differs from aprv-server

- **The two verify routes are not byte for byte the module's JSON.** The
  package returns objects for `verifyReceipt` and `verifySignedData`, not
  the module's text, so the Worker puts aprv-server's envelope back around
  the package's `payload.toJson()`, `environment`, `reason` and `message`.
  The members are the same; the bytes are not compared against
  aprv-server's. The two `verify-receipt` endpoint routes return the
  module's string unchanged.
- **`GET /v1/info` reports the package's version only.** The package
  exposes neither the roots' fingerprints nor the component's SHA-256, and
  the Worker does not compute them.
- **`max_input_bytes` is a constant in the Worker.** The package cuts an
  input at the length the module states but does not report that length,
  so the Worker repeats 3,145,729 to stop reading a body and to choose
  413. If the module's cap changes, change the constant.
- **`X-Aprv-Now-Ms` above 9007199254740991 is a 400**: the package's clock
  is a JavaScript number.
- **The body is decoded as UTF-8 before the package sees it**, because the
  package takes strings. A body that is not UTF-8 reaches the module with
  U+FFFD in place of the bad bytes, where aprv-server passes the bytes
  as they came. A leading UTF-8 byte order mark is dropped. A body under
  the cap can grow past it as bad bytes become three-byte U+FFFD, so the
  module then answers `TOO_LARGE` while the Worker's status is 200.
- **A failure inside the package is an answer, not a 500.** When the
  module traps or the clock fails, the package returns `INTERNAL_ERROR`
  (or `{"status":21009}` on the endpoint routes) and the Worker passes it
  on with 200; aprv-server answers 500 with `WASM_TRAP` or `ABI_ERROR`.
  The Worker answers 500 only when the package cannot be started or
  throws.
- **`HEAD` is a 405.** aprv-server answers `HEAD` on its `GET` routes; this
  Worker routes `GET` only.
- **No `X-Aprv-Token` and no `/openapi.json`.** This is a public demo. A
  private deployment would require a token on `/v1/` routes as aprv-server
  does, stored with `wrangler secret put`.
- **Apple's roots only.** There is no custom-roots option, so the
  repository's generated JWS fixtures, which chain to a generated test
  root, answer `UNTRUSTED_CHAIN` here. A JWS your own app received from
  the App Store verifies.

## Rate limiting

The endpoint is public, so `/v1/` routes are limited to 30 requests per
60 seconds per client address (`CF-Connecting-IP`) with the
[Workers Rate Limiting binding](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/),
set in [`wrangler.toml`](wrangler.toml). Over the limit the answer is 429
with a JSON problem body. The binding counts per Cloudflare location and
is eventually consistent, so it is a brake, not an exact quota: on the
deployed demo a loop of sequential requests from one address got its first
429 after 80 to 100 requests, not after 30.

A second layer belongs in front of the Worker: a WAF rate-limiting rule on
the route, which is configured in the Cloudflare dashboard (Security, WAF,
Rate limiting rules), not in this code.

## Logging

One line per request: method, path and status (a Worker's clock does not
advance while it computes, so a duration would always read 0). The Worker never
logs a body, a receipt or a payload, because a receipt carries a user's
purchase history. Keep it that way if you extend it.

## Deployed

https://aprv-example.emindeniz99.workers.dev, deployed on 2026-10-05 with
wrangler 4.147.0 and package 0.8.1, the WebAssembly core (every response
says which release in `X-Aprv-Version`). The Worker upload is 2,895 KiB,
958 KiB gzipped, and starts in 1 ms.

Checked against that URL: the public sandbox receipt verifies with
`"environment":"Sandbox"` on the Worker and in the browser, where the page
fetches the three `.wasm` core modules; a receipt with one character
flipped is refused; `/v1/verify-receipt/sandbox` answers `"status":0` and
`/production` `21007`; `X-Aprv-Now-Ms` sets `request_date_ms`; a body of
3,145,729 bytes is a 413 with `TOO_LARGE`.
