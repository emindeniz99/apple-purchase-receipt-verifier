"""The verifyReceipt-compatible endpoint: the published bound. The answer
comes from ``aprv.wasm``, which owns the bound; the constant here only
states it (docs/design/0.7-api.md §3)."""

#: Ceiling on the request body, in UTF-8 bytes: 3 MiB, Apple's own limit. A
#: larger body is ``Reason.TOO_LARGE`` (status 21002).
MAX_REQUEST_BYTES = 3145728
