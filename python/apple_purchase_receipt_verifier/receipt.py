"""Legacy app receipts: the published bounds and the caller-side device
hash. The verification itself runs in ``aprv.wasm``; the module owns every
bound, and the constants here only state them (docs/design/0.7-api.md §1)."""

import hashlib

#: Ceiling on the certificates a receipt may embed.
MAX_EMBEDDED_CERTIFICATES = 10
#: Ceiling on the SignerInfos a receipt may carry.
MAX_SIGNER_INFOS = 4


def device_hash(device_id: bytes, opaque_value: bytes, bundle_id_bytes: bytes) -> bytes:
    """SHA-1(``device_id`` + ``opaque_value`` + ``bundle_id_bytes``), the
    device-hash formula Apple's on-device check uses. Compare with
    :attr:`~.receipt_payload.ReceiptPayload.sha1_hash`. Not called by
    verification itself; the caller applies it (docs/design/0.7-api.md
    drops the built-in device-hash check)."""
    return hashlib.sha1(device_id + opaque_value + bundle_id_bytes).digest()
