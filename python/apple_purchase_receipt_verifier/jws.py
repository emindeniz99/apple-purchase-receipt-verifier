"""Apple-signed compact JWS: the published bound. The verification itself
runs in ``aprv.wasm``, which owns the bound; the constant here only states
it (docs/design/0.7-api.md §2)."""

#: Ceiling on the compact JWS, in UTF-8 bytes. Enforced by the module: a
#: larger JWS is ``Reason.TOO_LARGE``. Real Apple JWS payloads, Apple's own
#: mock notification data included, are under 2.5 KB, so 256 KiB is a
#: hundredfold headroom over anything Apple has ever signed.
MAX_JWS_BYTES = 262144
