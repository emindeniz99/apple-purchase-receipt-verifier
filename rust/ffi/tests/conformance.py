#!/usr/bin/env python3
"""Runs fixtures/cases.json through the C ABI, from Python, over ctypes.

    cargo build --locked --manifest-path rust/ffi/Cargo.toml
    python3 rust/ffi/tests/conformance.py <cargo target dir>/debug [--answers <dir>]

The compiled harness in ../examples/cpp is the primary one; this exists for
two reasons the C++ one cannot serve.

First, it is the evidence for the "any FFI-capable language" claim. Nothing
here is generated, pre-decoded or pre-flattened: it opens the same vector
file every port reads, hashes the fixtures itself, and calls the same
exported symbols a C compiler would, through ctypes, from a language with no
compiler in the loop at all.

Second, it checks the pointers C++ cannot reach. `/receipt/bundle_id`,
`/in_app/[product_id=com.example.app.vip]/expires_date_ms` and
`/unknown_attributes/9999/0` all resolve here, against a real JSON parser,
so the nested pointers the manifest generator drops for the C++ harness are
covered rather than lost.

It drives the `_bytes` calls, which take a pointer and a length and answer
the document aprv.wasm answers, so every case runs, the decodeBase64 groups
included: a receipt-data text goes through `aprv_verify_receipt_bytes`, an
x5c text as the three entries of a JWS header through
`aprv_verify_signed_data_bytes`, and which side of the base64 rule a text
landed on is read as tools/wasm-trap-host.mjs reads it (a decoder refusal
names base64). Every document is checked to be the wire shape
(`verified`, then `payload` or `reason` and `message`) with a status that
agrees; `--answers <dir>` also writes them, one per line, for
tools/validate-wire.mjs (verify-receipt.jsonl, verify-signed-data.jsonl).
After the run every case id in the file must have run.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import re
import sys
import time
from base64 import b64decode, b64encode, urlsafe_b64encode
from datetime import datetime, timezone
from pathlib import Path

# --- status codes, mirroring include/apple_purchase_receipt_verifier.h -----

OK = 0
# The ABI's reason codes, pinned as the header declares them.
REASON_CODES = {
    "MALFORMED": 13,
    "TOO_LARGE": 14,
    "INVALID_SIGNATURE": 5,
    "UNTRUSTED_CHAIN": 15,
    "INVALID_CERTIFICATE": 2,
    "INVALID_CERTIFICATE_PURPOSE": 3,
    "UNREADABLE_PAYLOAD": 16,
    "INTERNAL_ERROR": 12,
}

ENDPOINT_ENVIRONMENTS = {"PRODUCTION": 1, "SANDBOX": 2}

LIBRARY_NAMES = [
    "libapple_purchase_receipt_verifier_ffi.so",
    "libapple_purchase_receipt_verifier_ffi.dylib",
    "apple_purchase_receipt_verifier_ffi.dll",
]


class AprvResult(ctypes.Structure):
    # A void pointer, not c_char_p: ctypes would turn a c_char_p into bytes
    # and drop the pointer, and the pointer is what aprv_string_free needs.
    _fields_ = [("status", ctypes.c_int32), ("json", ctypes.c_void_p)]


def load_library(directory: Path) -> ctypes.CDLL:
    for name in LIBRARY_NAMES:
        if (directory / name).is_file():
            lib = ctypes.CDLL(str(directory / name))
            break
    else:
        raise SystemExit(f"no shared library in {directory}")
    u8p = ctypes.POINTER(ctypes.c_uint8)
    lib.aprv_version.restype = ctypes.c_char_p
    lib.aprv_verifier_new.argtypes = [
        ctypes.POINTER(u8p),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.aprv_verifier_new.restype = ctypes.c_void_p
    lib.aprv_verifier_free.argtypes = [ctypes.c_void_p]
    for name in ("aprv_verify_receipt_bytes", "aprv_verify_signed_data_bytes"):
        function = getattr(lib, name)
        function.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(AprvResult)]
        function.restype = ctypes.c_int32
    lib.aprv_verify_receipt_endpoint_bytes.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.aprv_verify_receipt_endpoint_bytes.restype = ctypes.c_int32
    lib.aprv_string_free.argtypes = [ctypes.c_void_p]
    return lib


def take_string(lib: ctypes.CDLL, pointer: int | None) -> str:
    """Reads a string the ABI handed out and frees it. Never leaks."""
    if not pointer:
        return ""
    text = ctypes.cast(pointer, ctypes.c_char_p).value or b""
    lib.aprv_string_free(ctypes.c_void_p(pointer))
    return text.decode("utf-8")


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


def receipt_string(directory: Path, registry: dict, name: str) -> bytes:
    """What verifyReceipt gets, and the endpoint's receipt-data: a text
    fixture verbatim, exactly as a client sent it; any other fixture holds
    DER, encoded as canonical base64."""
    data = fixture_bytes(directory, registry, name)
    return data if registry[name]["codec"] == "text" else b64encode(data)


def clock_millis(case: dict):
    """The case's pinned instant as epoch milliseconds, or `None`."""
    spec = case.get("clock")
    if not spec:
        return None
    text = spec["now"]
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit(f'{case["id"]}: unparseable clock "{text}"') from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return round(moment.timestamp() * 1000)


# --- pointers -------------------------------------------------------------

MISSING = object()


def resolve(root, pointer: str):
    """An RFC 6901 pointer with one extension: a token `[key=value]` selects
    the single array element whose member `key` is the JSON string `value`,
    and the case fails unless exactly one matches."""
    if not pointer.startswith("/"):
        raise SystemExit(f'"{pointer}" is not a pointer')
    current = root
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if token.startswith("[") and token.endswith("]") and "=" in token:
            key, value = token[1:-1].split("=", 1)
            if not isinstance(current, list):
                return MISSING
            matches = [e for e in current if isinstance(e, dict) and e.get(key) == value]
            if len(matches) != 1:
                raise ValueError(f"{token} matches {len(matches)} elements")
            current = matches[0]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                return MISSING
            current = current[int(token)]
        elif isinstance(current, dict):
            if token not in current:
                return MISSING
            current = current[token]
        else:
            return MISSING
    return current


def same_value(actual, wanted) -> bool:
    """null means absent or JSON null; numbers compare by value and integers
    exactly (json.loads keeps every integer's digits); booleans are not
    numbers."""
    if wanted is None:
        return actual is MISSING or actual is None
    if isinstance(wanted, bool) or isinstance(actual, bool):
        return actual is wanted
    if isinstance(wanted, (int, float)) and isinstance(actual, (int, float)):
        return actual == wanted
    return actual == wanted


# --- one case -------------------------------------------------------------


def verifier_for(lib, directory: Path, registry: dict, case: dict):
    """The verifier a case's config describes, and the buffers it borrowed."""
    roots = case["config"]["trustedRoots"]
    keep = []
    if roots["source"] == "defaults":
        ders, lens, count = None, None, 0
    elif roots["source"] == "fixtures":
        names = roots["fixtures"]
        buffers = []
        for name in names:
            data = fixture_bytes(directory, registry, name)
            buffers.append((ctypes.c_uint8 * len(data)).from_buffer_copy(data))
        keep.extend(buffers)
        u8p = ctypes.POINTER(ctypes.c_uint8)
        ders = (u8p * len(buffers))(*[ctypes.cast(b, u8p) for b in buffers])
        lens = (ctypes.c_size_t * len(buffers))(*[len(b) for b in buffers])
        count = len(buffers)
    else:
        raise SystemExit(f'{case["id"]}: unknown trustedRoots source {roots["source"]}')
    millis = clock_millis(case)
    clock = None if millis is None else ctypes.byref(ctypes.c_int64(millis))
    verifier = lib.aprv_verifier_new(ders, lens, count, clock)
    if not verifier:
        raise SystemExit(f'{case["id"]}: aprv_verifier_new refused the configuration')
    return verifier, keep


ANSWERS: dict[str, list[str]] = {"verify-receipt": [], "verify-signed-data": []}


def call_bytes(lib, verifier, function: str, data: bytes):
    """(status, wire document) for one `_bytes` call; checks the document's
    shape and that its verdict agrees with the status."""
    result = AprvResult()
    status = getattr(lib, f"aprv_{function.replace('-', '_')}_bytes")(verifier, data, len(data), ctypes.byref(result))
    if status >= 100:
        raise SystemExit(f"{function}: the call itself failed with {status}")
    text = take_string(lib, result.json)
    ANSWERS[function].append(text)
    document = json.loads(text)
    keys = list(document)
    if status == OK:
        if keys != ["verified", "payload"] or document["verified"] is not True:
            raise SystemExit(f"{function}: status 0 with the document {text[:200]}")
    elif keys != ["verified", "reason", "message"] or document["verified"] is not False or REASON_CODES.get(document["reason"]) != status:
        raise SystemExit(f"{function}: status {status} with the document {text[:200]}")
    return status, document


def payload_text(document) -> str:
    """What the checks read: the payload JSON (a JWS payload is the signed
    text, which the wire carries as a string), or the failure document."""
    if document["verified"] is not True:
        return json.dumps(document)
    payload = document["payload"]
    return payload if isinstance(payload, str) else json.dumps(payload)


def x5c_probe(text: str) -> bytes:
    """A JWS whose header carries `text` as every x5c entry, as the trap host builds it."""
    b64url = lambda b: urlsafe_b64encode(b).rstrip(b"=")
    header = json.dumps({"alg": "ES256", "x5c": [text, text, text]}, separators=(",", ":")).encode()
    return b64url(header) + b"." + b64url(b"{}") + b"." + b64url(b"signature")


def run_decode(lib, case: dict) -> str:
    """A decodeBase64 group through the verify calls; an empty string when
    every text lands on its group's side of the rule."""
    verifier = lib.aprv_verifier_new(None, None, 0, None)
    problems = []
    try:
        for decoder in case["decoders"]:
            for index, text in enumerate(case["input"]["texts"]):
                if decoder == "receipt-data":
                    status, document = call_bytes(lib, verifier, "verify-receipt", text.encode("utf-8"))
                    refusal = "MALFORMED"
                elif decoder == "x5c":
                    status, document = call_bytes(lib, verifier, "verify-signed-data", x5c_probe(text))
                    refusal = "INVALID_CERTIFICATE"
                else:
                    raise SystemExit(f'{case["id"]}: no decoder {decoder}')
                refused = (
                    document["verified"] is False
                    and document["reason"] == refusal
                    and (text == "" or re.search("base64", document["message"], re.I) is not None)
                )
                where = f"{decoder} texts[{index}] {json.dumps(text)[:40]}"
                if document["verified"] is True:
                    problems.append(f"{where} verified")
                elif case["expected"]["status"] == "error" and not refused:
                    problems.append(f'{where} not refused by the decoder: {document["reason"]} {document["message"]}')
                elif case["expected"]["status"] == "ok" and refused:
                    problems.append(f'{where} refused by the decoder: {document["message"]}')
    finally:
        lib.aprv_verifier_free(verifier)
    return "; ".join(problems)


def run_case(lib, directory: Path, registry: dict, case: dict):
    """(status, JSON text) for one case: the payload when verified, the
    failure document otherwise, the body for the endpoint."""
    verifier, _keep = verifier_for(lib, directory, registry, case)
    try:
        operation = case["operation"]
        source = case["input"]
        if operation == "verifyReceiptEndpoint":
            if "requestBody" in source:
                body = fixture_bytes(directory, registry, source["requestBody"])
            else:
                receipt = receipt_string(directory, registry, source["fixture"]).decode("utf-8")
                body = json.dumps({"receipt-data": receipt}).encode("utf-8")
            environment = ENDPOINT_ENVIRONMENTS[case["config"]["environment"]]
            response = ctypes.c_void_p()
            status = lib.aprv_verify_receipt_endpoint_bytes(
                verifier, environment, body, len(body), ctypes.byref(response)
            )
            if status != OK:
                raise SystemExit(f'{case["id"]}: the endpoint call itself failed with {status}')
            return OK, take_string(lib, response.value)
        if operation == "verifyReceipt":
            data = receipt_string(directory, registry, source["fixture"])
            function = "verify-receipt"
        elif operation == "verifySignedData":
            data = fixture_bytes(directory, registry, source["fixture"])
            function = "verify-signed-data"
        else:
            raise SystemExit(f'{case["id"]}: no adapter for operation {operation}')
        status, document = call_bytes(lib, verifier, function, data)
        return status, payload_text(document)
    finally:
        lib.aprv_verifier_free(verifier)


def check(case: dict, status: int, text: str) -> str:
    """An empty string when the case passes, else what went wrong."""
    expected = case["expected"]
    if case["operation"] == "verifyReceiptEndpoint" and "oneOf" in expected:
        # Port-defined within a list: the body's status must be listed, and
        # nothing else is pinned.
        if status != OK:
            return f"the endpoint call itself failed with {status}: {text}"
        got = json.loads(text).get("status")
        return "" if got in expected["oneOf"] else f'expected status one of {expected["oneOf"]}, got {got}: {text}'
    if "oneOf" in expected:
        # A panic answers INTERNAL_ERROR, which no list holds.
        allowed = [OK if o == "ok" else REASON_CODES[o] for o in expected["oneOf"]]
        return "" if status in allowed else f'expected one of {expected["oneOf"]}, got status {status}: {text}'
    if case["operation"] != "verifyReceiptEndpoint" and expected.get("status") == "error":
        wanted = REASON_CODES[expected["reason"]]
        if status != wanted:
            return f'expected {expected["reason"]} ({wanted}), got status {status}: {text}'
        if json.loads(text).get("reason") != expected["reason"]:
            return f'the error body does not name {expected["reason"]}: {text}'
        return ""
    if status != OK:
        return f"expected success, got status {status}: {text}"
    # Same value, not same bytes. Re-encoding both sides with sorted keys
    # ignores key order and escaping but, unlike ==, tells true from 1.
    if "toJson" in expected and json.dumps(json.loads(text), sort_keys=True) != json.dumps(
        json.loads(expected["toJson"]), sort_keys=True
    ):
        return f"toJson value differs: got {text}"
    document = json.loads(text)
    for pointer, wanted in (expected.get("fields") or {}).items():
        try:
            actual = resolve(document, pointer)
        except ValueError as error:
            return f"{pointer}: {error}"
        if not same_value(actual, wanted):
            shown = "nothing" if actual is MISSING else json.dumps(actual)
            return f"{pointer}: expected {json.dumps(wanted)}, got {shown}"
    for pointer, wanted in (expected.get("lengths") or {}).items():
        try:
            actual = resolve(document, pointer)
        except ValueError as error:
            return f"{pointer}: {error}"
        if not isinstance(actual, list) or len(actual) != wanted:
            return f"{pointer}: expected length {wanted}, got {actual!r}"
    return ""


def main() -> int:
    args = sys.argv[1:]
    answers = None
    if "--answers" in args:
        at = args.index("--answers")
        answers = Path(args[at + 1])
        del args[at : at + 2]
    if len(args) != 1:
        print(f"usage: {sys.argv[0]} <directory holding the built shared library> [--answers <dir>]", file=sys.stderr)
        return 2
    lib = load_library(Path(args[0]))
    directory = fixtures_dir(Path(__file__).parent)
    file = json.loads((directory / "cases.json").read_text(encoding="utf-8"))
    if file["schemaVersion"] != 2:
        raise SystemExit(f'cases.json is schemaVersion {file["schemaVersion"]}, this adapter is 2')
    registry = file["fixtures"]

    print(
        f"apple-purchase-receipt-verifier {lib.aprv_version().decode()}: "
        "C ABI conformance over ctypes"
    )

    # The whole registry first: a fixture no case references would otherwise
    # drift unnoticed, and the digest guarantee is over the registry.
    for name in registry:
        fixture_bytes(directory, registry, name)

    passed = failed = 0
    ran: set[str] = set()
    pinned_clocks = 0
    checked = 0
    decode_groups = 0
    for case in file["cases"]:
        ran.add(case["id"])
        if case["operation"] == "decodeBase64":
            decode_groups += 1
            problem = run_decode(lib, case)
            if problem:
                print(f'FAIL  {case["id"]}: {problem}', file=sys.stderr)
                failed += 1
            else:
                passed += 1
            continue
        if case.get("clock"):
            pinned_clocks += 1
        expected = case["expected"]
        checked += len(expected.get("fields") or {}) + len(expected.get("lengths") or {})
        budget = case.get("maxMillis")
        if budget is not None:
            # The denial-of-service cases: one warm-up run of the same case,
            # then the timed run whose outcome is checked.
            run_case(lib, directory, registry, case)
            start = time.perf_counter()
        status, text = run_case(lib, directory, registry, case)
        problem = check(case, status, text)
        if budget is not None and not problem:
            millis = (time.perf_counter() - start) * 1000
            if millis > budget:
                problem = f"took {millis:.0f} ms, over the {budget} ms budget"
        if problem:
            print(f'FAIL  {case["id"]}: {problem}', file=sys.stderr)
            failed += 1
        else:
            passed += 1

    print(f"{passed} passed, {failed} failed, 0 skipped ({pinned_clocks} pin a clock)")
    print(f"{checked} expected fields and lengths checked, nested pointers included")
    print(f"{decode_groups} decodeBase64 groups through the verify calls")
    if answers is not None:
        answers.mkdir(parents=True, exist_ok=True)
        for function, lines in ANSWERS.items():
            (answers / f"{function}.jsonl").write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")
        print(f"{sum(len(v) for v in ANSWERS.values())} documents written to {answers}")
    if passed == 0:
        print("no case ran", file=sys.stderr)
        return 2
    # Coverage self-check: every case id in the parsed file ran, never
    # compared against a literal count.
    missing = [c["id"] for c in file["cases"] if c["id"] not in ran]
    if missing:
        print(
            f"{len(missing)} of {len(file['cases'])} cases did not run: {', '.join(missing)}",
            file=sys.stderr,
        )
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
