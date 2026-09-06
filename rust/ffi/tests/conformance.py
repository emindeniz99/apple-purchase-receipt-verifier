#!/usr/bin/env python3
"""Runs fixtures/cases.json through the C ABI, from Python, over ctypes.

    cargo build --locked --manifest-path rust/ffi/Cargo.toml
    python3 rust/ffi/tests/conformance.py <cargo target dir>/debug

The compiled harness in ../examples/cpp is the primary one; this exists for
two reasons the C++ one cannot serve.

First, it is the evidence for the "any FFI-capable language" claim. Nothing
here is generated, pre-decoded or pre-flattened: it opens the same
cases.json every port reads, hashes the fixtures itself, and calls the same
exported symbols a C compiler would — through ctypes, from a language with
no compiler in the loop at all.

Second, it checks the field paths C++ cannot reach. `receipt.bundle_id`,
`inAppPurchases[productId=com.example.app.vip].expiresDate`,
`unknownAttributes[9999][0]` and `inAppPurchases.length` all resolve here,
against a real JSON parser, so the 51 paths the manifest generator drops for
the C++ harness are covered rather than lost.

Both harnesses skip the same 12 cases, for the same stated reason: they pin
a clock, and the C ABI has no clock argument. That is asserted, not assumed
— an unsupported case with any other cause fails the run.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import re
import sys
from base64 import b64decode, b64encode
from pathlib import Path

# --- status codes, mirroring include/apple_purchase_receipt_verifier.h -----

OK = 0
REASONS = [
    "INVALID_JWS_FORMAT",
    "INVALID_CERTIFICATE",
    "INVALID_CERTIFICATE_PURPOSE",
    "INVALID_CHAIN",
    "INVALID_SIGNATURE",
    "WRONG_BUNDLE_ID",
    "WRONG_ENVIRONMENT",
    "WRONG_APP_APPLE_ID",
    "INVALID_RECEIPT_FORMAT",
    "DEVICE_HASH_MISMATCH",
    "STALE_PAYLOAD",
]
REASON_CODES = {token: index + 1 for index, token in enumerate(REASONS)}

ENVIRONMENT_BITS = {"Production": 1, "Sandbox": 2, "Xcode": 4, "LocalTesting": 8}

# verifyRaw enforces no claim, so its cases may omit both, and the ABI still
# demands them. These match nothing any fixture carries, so a claim check
# that leaked into verify_raw fails the case rather than passing it.
UNMATCHABLE_BUNDLE_ID = "conformance.unset.bundle.id"
UNMATCHABLE_ENVIRONMENTS = ENVIRONMENT_BITS["LocalTesting"]

LIBRARY_NAMES = [
    "libapple_purchase_receipt_verifier_ffi.so",
    "libapple_purchase_receipt_verifier_ffi.dylib",
    "apple_purchase_receipt_verifier_ffi.dll",
]


class AprvResult(ctypes.Structure):
    # `json` is a void pointer rather than a c_char_p because ctypes turns a
    # c_char_p return into bytes and throws the pointer away — and the
    # pointer is what aprv_string_free needs.
    _fields_ = [("status", ctypes.c_int32), ("json", ctypes.c_void_p)]


def load_library(directory: Path) -> ctypes.CDLL:
    for name in LIBRARY_NAMES:
        candidate = directory / name
        if candidate.is_file():
            break
    else:
        raise SystemExit(
            f"no shared library in {directory}; expected one of {', '.join(LIBRARY_NAMES)}. "
            "Run: cargo build --locked --manifest-path rust/ffi/Cargo.toml"
        )

    lib = ctypes.CDLL(str(candidate))
    u8p = ctypes.POINTER(ctypes.c_uint8)
    u8pp = ctypes.POINTER(u8p)
    sizep = ctypes.POINTER(ctypes.c_size_t)
    result = ctypes.POINTER(AprvResult)

    lib.aprv_version.argtypes = []
    lib.aprv_version.restype = ctypes.c_char_p

    lib.aprv_verifier_new_jws.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.c_uint64,
        ctypes.c_uint64,
    ]
    lib.aprv_verifier_new_jws.restype = ctypes.c_void_p
    lib.aprv_verifier_new_jws_with_roots.argtypes = [
        ctypes.c_char_p,
        ctypes.c_uint32,
        ctypes.c_uint64,
        ctypes.c_uint64,
        u8pp,
        sizep,
        ctypes.c_size_t,
    ]
    lib.aprv_verifier_new_jws_with_roots.restype = ctypes.c_void_p
    lib.aprv_verifier_free_jws.argtypes = [ctypes.c_void_p]
    lib.aprv_verifier_free_jws.restype = None

    lib.aprv_verifier_new_receipt.argtypes = [ctypes.c_char_p]
    lib.aprv_verifier_new_receipt.restype = ctypes.c_void_p
    lib.aprv_verifier_new_receipt_with_roots.argtypes = [
        ctypes.c_char_p,
        u8pp,
        sizep,
        ctypes.c_size_t,
    ]
    lib.aprv_verifier_new_receipt_with_roots.restype = ctypes.c_void_p
    lib.aprv_verifier_free_receipt.argtypes = [ctypes.c_void_p]
    lib.aprv_verifier_free_receipt.restype = None

    lib.aprv_endpoint_new.argtypes = [ctypes.c_uint32]
    lib.aprv_endpoint_new.restype = ctypes.c_void_p
    lib.aprv_endpoint_new_with_roots.argtypes = [ctypes.c_uint32, u8pp, sizep, ctypes.c_size_t]
    lib.aprv_endpoint_new_with_roots.restype = ctypes.c_void_p
    lib.aprv_endpoint_free.argtypes = [ctypes.c_void_p]
    lib.aprv_endpoint_free.restype = None

    for name in ("aprv_verify_transaction", "aprv_verify_app_transaction", "aprv_verify_raw"):
        function = getattr(lib, name)
        function.argtypes = [ctypes.c_void_p, ctypes.c_char_p, result]
        function.restype = ctypes.c_int32

    lib.aprv_verify_receipt_der.argtypes = [ctypes.c_void_p, u8p, ctypes.c_size_t, result]
    lib.aprv_verify_receipt_der.restype = ctypes.c_int32
    lib.aprv_verify_receipt_der_with_device_guid.argtypes = [
        ctypes.c_void_p,
        u8p,
        ctypes.c_size_t,
        u8p,
        ctypes.c_size_t,
        result,
    ]
    lib.aprv_verify_receipt_der_with_device_guid.restype = ctypes.c_int32
    lib.aprv_verify_receipt_base64.argtypes = [ctypes.c_void_p, ctypes.c_char_p, result]
    lib.aprv_verify_receipt_base64.restype = ctypes.c_int32
    lib.aprv_verify_receipt_base64_with_device_guid.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        u8p,
        ctypes.c_size_t,
        result,
    ]
    lib.aprv_verify_receipt_base64_with_device_guid.restype = ctypes.c_int32
    lib.aprv_verify_receipt_endpoint_json.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.aprv_verify_receipt_endpoint_json.restype = ctypes.c_int32

    lib.aprv_string_free.argtypes = [ctypes.c_void_p]
    lib.aprv_string_free.restype = None
    return lib


def take_string(lib: ctypes.CDLL, pointer: int | None) -> str:
    """Reads a string the ABI handed out and frees it. Never leaks."""
    if not pointer:
        return ""
    text = ctypes.cast(pointer, ctypes.c_char_p).value or b""
    lib.aprv_string_free(ctypes.c_void_p(pointer))
    return text.decode("utf-8")


def byte_array(data: bytes):
    """A `const uint8_t *` over `data`, valid while the returned buffer is."""
    buffer = (ctypes.c_uint8 * max(len(data), 1)).from_buffer_copy(data + b"\0")
    return buffer, ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8))


# --- the vector file ------------------------------------------------------


def fixtures_dir(start: Path) -> Path:
    directory = start.resolve()
    while True:
        candidate = directory / "fixtures"
        if (candidate / "cases.json").is_file():
            return candidate
        if directory.parent == directory:
            raise SystemExit("no fixtures/cases.json above this script")
        directory = directory.parent


def fixture_bytes(directory: Path, registry: dict, name: str) -> bytes:
    entry = registry.get(name)
    if entry is None:
        raise SystemExit(f'cases.json registers no fixture "{name}"')
    raw = (directory / entry["path"]).read_bytes()
    codec = entry["codec"]
    if codec in ("raw", "text"):
        data = raw
    elif codec == "utf8":
        data = raw.decode("utf-8").strip().encode("utf-8")
    elif codec == "base64":
        data = b64decode(re.sub(rb"\s+", b"", raw))
    else:
        raise SystemExit(f'fixture "{name}" has unknown codec "{codec}"')
    digest = hashlib.sha256(data).hexdigest()
    if digest != entry["contentSha256"]:
        raise SystemExit(
            f'fixture "{name}" ({entry["path"]}, codec {codec}) has drifted: '
            f'cases.json records {entry["contentSha256"]}, the decoded bytes hash to {digest}'
        )
    return data


# --- language-neutral field paths ----------------------------------------


def path_steps(path: str) -> list:
    """`bundleId`, `inAppPurchases.length`, `unknownAttributes[9999][0]`,
    `inAppPurchases[productId=com.example.app.vip].expiresDate`. Bracket
    contents hold dots and equals signs, so a plain split is wrong."""
    steps: list = []
    current = ""
    index = 0
    while index < len(path):
        char = path[index]
        if char == ".":
            if current:
                steps.append(("name", current))
                current = ""
        elif char == "[":
            if current:
                steps.append(("name", current))
                current = ""
            close = path.index("]", index)
            steps.append(("bracket", path[index + 1 : close]))
            index = close
        else:
            current += char
        index += 1
    if current:
        steps.append(("name", current))
    if not steps:
        raise SystemExit(f'unparseable field path "{path}"')
    return steps


MISSING = object()


def resolve_path(root, path: str):
    current = root
    for kind, step in path_steps(path):
        if current is None:
            return None
        if kind == "name":
            if step == "length" and isinstance(current, list):
                return len(current)
            if not isinstance(current, dict) or step not in current:
                return MISSING
            current = current[step]
            continue
        if "=" in step and not step.startswith("="):
            key, _, wanted = step.partition("=")
            if not isinstance(current, list):
                raise SystemExit(f"{path}: [{step}] does not select from a list")
            matches = [item for item in current if isinstance(item, dict) and item.get(key) == wanted]
            if len(matches) != 1:
                raise SystemExit(
                    f"{path}: [{step}] must select exactly one element, selected {len(matches)}"
                )
            current = matches[0]
            continue
        if isinstance(current, list):
            index = int(step)
            if index >= len(current):
                return MISSING
            current = current[index]
        else:
            if not isinstance(current, dict) or step not in current:
                return MISSING
            current = current[step]
    return current


# --- one case -------------------------------------------------------------


def anchors_for(directory: Path, registry: dict, spec: dict):
    """The `(ders, lens, count, keepalive)` quadruple, or `None` for the
    bundled Apple roots."""
    if spec["source"] == "builtin":
        if spec.get("name") not in ("apple-jws-roots", "apple-receipt-roots"):
            raise SystemExit(f'unknown builtin root set {spec.get("name")!r}')
        return None
    if spec["source"] != "fixtures":
        raise SystemExit(f'unknown trustedRoots source "{spec["source"]}"')
    blobs = [fixture_bytes(directory, registry, name) for name in spec["fixtures"]]
    keepalive = [(ctypes.c_uint8 * len(blob)).from_buffer_copy(blob) for blob in blobs]
    ders = (ctypes.POINTER(ctypes.c_uint8) * len(blobs))(
        *[ctypes.cast(buffer, ctypes.POINTER(ctypes.c_uint8)) for buffer in keepalive]
    )
    lens = (ctypes.c_size_t * len(blobs))(*[len(blob) for blob in blobs])
    return ders, lens, len(blobs), keepalive


def run_case(lib, directory: Path, registry: dict, case: dict):
    """Returns `(status, parsed_json)`; raises SystemExit on a harness fault."""
    config = case["config"]
    operation = case["operation"]
    anchors = anchors_for(directory, registry, config["trustedRoots"])
    data = fixture_bytes(directory, registry, case["input"]["fixture"])

    bundle_id = (config.get("bundleId") or UNMATCHABLE_BUNDLE_ID).encode("utf-8")
    mask = 0
    for name in config.get("acceptedEnvironments") or []:
        mask |= ENVIRONMENT_BITS[name]
    mask = mask or UNMATCHABLE_ENVIRONMENTS
    app_apple_id = config.get("appAppleId") or 0
    max_age = config.get("maxSignedAgeSeconds") or 0
    guid = bytes.fromhex(config["deviceGuidHex"]) if config.get("deviceGuidHex") else b""

    result = AprvResult()

    if operation in ("verifyTransaction", "verifyAppTransaction", "verifyRaw"):
        if anchors is None:
            handle = lib.aprv_verifier_new_jws(bundle_id, mask, app_apple_id, max_age)
        else:
            ders, lens, count, _keepalive = anchors
            handle = lib.aprv_verifier_new_jws_with_roots(
                bundle_id, mask, app_apple_id, max_age, ders, lens, count
            )
        if not handle:
            raise SystemExit(f'{case["id"]}: aprv_verifier_new_jws refused the configuration')
        call = {
            "verifyTransaction": lib.aprv_verify_transaction,
            "verifyAppTransaction": lib.aprv_verify_app_transaction,
            "verifyRaw": lib.aprv_verify_raw,
        }[operation]
        call(handle, data, ctypes.byref(result))
        lib.aprv_verifier_free_jws(handle)

    elif operation in ("verifyReceipt", "verifyReceiptBase64"):
        if anchors is None:
            handle = lib.aprv_verifier_new_receipt(bundle_id)
        else:
            ders, lens, count, _keepalive = anchors
            handle = lib.aprv_verifier_new_receipt_with_roots(bundle_id, ders, lens, count)
        if not handle:
            raise SystemExit(f'{case["id"]}: aprv_verifier_new_receipt refused the configuration')
        guid_buffer, guid_pointer = byte_array(guid)
        if operation == "verifyReceipt":
            payload_buffer, payload_pointer = byte_array(data)
            if guid:
                lib.aprv_verify_receipt_der_with_device_guid(
                    handle, payload_pointer, len(data), guid_pointer, len(guid), ctypes.byref(result)
                )
            else:
                lib.aprv_verify_receipt_der(
                    handle, payload_pointer, len(data), ctypes.byref(result)
                )
            del payload_buffer
        else:
            if guid:
                lib.aprv_verify_receipt_base64_with_device_guid(
                    handle, data, guid_pointer, len(guid), ctypes.byref(result)
                )
            else:
                lib.aprv_verify_receipt_base64(handle, data, ctypes.byref(result))
        del guid_buffer
        lib.aprv_verifier_free_receipt(handle)

    elif operation == "verifyReceiptEndpoint":
        environment = ENVIRONMENT_BITS[config["environment"]]
        if anchors is None:
            handle = lib.aprv_endpoint_new(environment)
        else:
            ders, lens, count, _keepalive = anchors
            handle = lib.aprv_endpoint_new_with_roots(environment, ders, lens, count)
        if not handle:
            raise SystemExit(f'{case["id"]}: aprv_endpoint_new refused the configuration')
        # A "text" fixture carries the exact string a client sent; raw and
        # base64 fixtures have no client-facing string of their own, so they
        # are re-encoded as canonical base64. Same rule as every other port.
        codec = registry[case["input"]["fixture"]]["codec"]
        receipt_data = data.decode("utf-8") if codec == "text" else b64encode(data).decode("ascii")
        body = json.dumps({"receipt-data": receipt_data}).encode("utf-8")
        response = ctypes.c_void_p()
        status = lib.aprv_verify_receipt_endpoint_json(handle, body, ctypes.byref(response))
        lib.aprv_endpoint_free(handle)
        if status != OK:
            raise SystemExit(f'{case["id"]}: the endpoint call failed with status {status}')
        return OK, json.loads(take_string(lib, response.value))

    else:
        raise SystemExit(f'no adapter for operation "{operation}"')

    text = take_string(lib, result.json)
    return result.status, (json.loads(text) if text else None)


def check(case: dict, status: int, payload) -> str:
    """The failure message, or an empty string."""
    expected = case["expected"]
    if expected["status"] == "error":
        wanted = REASON_CODES.get(expected["reason"])
        if wanted is None:
            return f'unknown expected reason {expected["reason"]}'
        if status != wanted:
            return f'reason: expected {expected["reason"]} ({wanted}), got status {status} {payload}'
        if not isinstance(payload, dict) or payload.get("reason") != expected["reason"]:
            return f'the error body does not name {expected["reason"]}: {payload}'
        return ""

    if status != OK:
        return f"expected success, got status {status} {payload}"
    for path, wanted in (expected.get("fields") or {}).items():
        found = resolve_path(payload, path)
        if wanted is None:
            if found not in (MISSING, None):
                return f"{path}: expected absent, got {found!r}"
            continue
        if found is MISSING:
            return f"{path}: expected {wanted!r}, got nothing"
        if found != wanted:
            return f"{path}: expected {wanted!r}, got {found!r}"
    return ""


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <directory holding the built shared library>", file=sys.stderr)
        return 2
    lib = load_library(Path(sys.argv[1]))
    directory = fixtures_dir(Path(__file__).parent)
    file = json.loads((directory / "cases.json").read_text(encoding="utf-8"))
    if file["schemaVersion"] != 1:
        raise SystemExit(f'cases.json is schemaVersion {file["schemaVersion"]}, this adapter is 1')
    registry = file["fixtures"]

    print(
        f'apple-purchase-receipt-verifier {lib.aprv_version().decode()} '
        "— C ABI conformance over ctypes"
    )

    # The whole registry first: a fixture no case references would otherwise
    # drift unnoticed, and the digest guarantee is over the registry.
    for name in registry:
        fixture_bytes(directory, registry, name)

    passed = failed = skipped = 0
    checked_fields = 0
    for case in file["cases"]:
        if case.get("clock"):
            # The only sanctioned reason a case cannot run here: the ABI has
            # no clock argument, because injecting one would mean a callback
            # and the surface is deliberately callback-free.
            skipped += 1
            continue
        checked_fields += len(case["expected"].get("fields") or {})
        status, payload = run_case(lib, directory, registry, case)
        problem = check(case, status, payload)
        if problem:
            print(f'FAIL  {case["id"]}: {problem}', file=sys.stderr)
            failed += 1
        else:
            passed += 1

    print(
        f"{passed} passed, {failed} failed, "
        f"{skipped} not runnable through the C ABI (no clock argument)"
    )
    print(f"{checked_fields} expected fields checked, nested paths included")
    if passed == 0:
        print("no case ran", file=sys.stderr)
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
