"""Runs fixtures/cases.json (the normative cross-language 0.7
conformance vectors) against this implementation. The adapter below knows
nothing about any individual case: it loads the file, resolves fixture ids
to bytes, builds a ``Config``/``Verifier`` from the generic config,
dispatches on "operation", normalizes the result and reads the reason off a
failure. A vector that disagrees with the library is a bug report against
one of the two; it is never something to special-case here.

The package holds no verification logic, so a case that fails here is a
fault of ``aprv.wasm`` (or of the wrapper's mapping of its JSON), never of
Python code. Every case must pass."""

import base64
import hashlib
import json
import re
import sys
import time
import unittest
from datetime import datetime
from pathlib import Path

from apple_purchase_receipt_verifier import Config, Environment, Reason, Verifier

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
# Read as UTF-8 explicitly rather than in the locale encoding: the file
# carries non-ASCII characters in its comments, and a machine whose locale
# resolves to ASCII would fail here before a single vector runs.
CASES = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))


def case_clock(case):
    """The ``clock.now`` of a case as a zero-argument callable returning
    epoch milliseconds. ``None`` for a case that pins no time, in which case
    ``Config()``'s system clock runs."""
    clock = case.get("clock")
    if clock is None:
        return None
    moment = datetime.fromisoformat(clock["now"].replace("Z", "+00:00"))
    millis = int(moment.timestamp() * 1000)
    return lambda: millis


def fixture_bytes(fixture_id):
    """Decodes a registered fixture to its logical bytes (fixture.codec),
    and checks them against the digest cases.json records for it."""
    entry = CASES["fixtures"].get(fixture_id)
    if entry is None:
        raise AssertionError(f"harness error: cases.json registers no fixture {fixture_id!r}")
    # read_bytes(), not a text-mode open(): the "text" codec's contract is
    # the file bytes VERBATIM, and a text-mode read on a platform whose
    # default newline handling translates line endings would silently
    # rewrite the CRLF fixtures before contentSha256 ever sees them.
    raw = (FIXTURES / entry["path"]).read_bytes()
    codec = entry["codec"]
    if codec == "raw":
        content = raw
    elif codec == "base64":
        content = base64.b64decode(re.sub(r"\s+", "", raw.decode("ascii")))
    elif codec == "utf8":
        content = raw.decode("utf-8").strip().encode("utf-8")
    elif codec == "text":
        raw.decode("utf-8")  # validates; the codec is untrimmed, so raw IS the content
        content = raw
    else:
        raise AssertionError(f"harness error: unknown fixture codec {codec!r}")
    expected = entry.get("contentSha256")
    if expected is None:
        raise AssertionError(f"harness error: fixture {fixture_id!r} records no contentSha256")
    actual = hashlib.sha256(content).hexdigest()
    if actual != expected:
        raise AssertionError(
            f"fixture {fixture_id!r} ({entry['path']}) does not match the digest "
            f"cases.json records: expected {expected}, got {actual}"
        )
    return content


def trusted_roots(spec):
    if spec["source"] == "defaults":
        return Config().roots  # None: the module's Apple roots
    return [fixture_bytes(i) for i in spec["fixtures"]]


def _config(case):
    clock = case_clock(case)
    kwargs = {"roots": trusted_roots(case["config"]["trustedRoots"])}
    if clock is not None:
        kwargs["clock"] = clock
    return Config(**kwargs)


def _receipt_string(data, codec):
    # verifyReceipt: a text fixture is handed over verbatim; a raw/base64
    # fixture holds DER, re-encoded as canonical standard base64.
    return data.decode("utf-8") if codec == "text" else base64.b64encode(data).decode("ascii")


def _op_verify_receipt(case, data, codec):
    verifier = Verifier(_config(case))
    return verifier.verify_receipt(_receipt_string(data, codec))


def _op_verify_signed_data(case, data, codec):
    verifier = Verifier(_config(case))
    # The fixture's logical bytes as a string: utf8 trims, text does not
    # (both are already the "logical bytes" fixture_bytes returns).
    return verifier.verify_signed_data(data.decode("utf-8"))


def _op_verify_receipt_endpoint(case, data, codec):
    verifier = Verifier(_config(case))
    environment = Environment[case["config"]["environment"]]
    request_body = case["input"].get("requestBody")
    if request_body is not None:
        request_json = data.decode("utf-8")
    else:
        request_json = json.dumps({"receipt-data": _receipt_string(data, codec)})
    return verifier.verify_receipt_endpoint(environment, request_json)


OPERATIONS = {
    "verifyReceipt": _op_verify_receipt,
    "verifySignedData": _op_verify_signed_data,
    "verifyReceiptEndpoint": _op_verify_receipt_endpoint,
}


# --- decodeBase64 -------------------------------------------------------

# 0.7 exposes no public decoder, and this package holds none. The rule is the
# module's, so each text is run through the public API where the module reads
# it, and must land on its group's side of the rule: refused as base64, or
# decoded and refused later for what the bytes are. The two are told apart by
# the failure message naming base64, which is the only place the module says
# which rule refused (a message is not a contract, so only this harness reads
# it). A receipt-data text is a receipt; an x5c text is the three chain
# entries of a JWS header, which the module decodes in order.


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jws_with_x5c(text):
    header = json.dumps({"alg": "ES256", "x5c": [text, text, text]}).encode("utf-8")
    return ".".join([_b64url(header), _b64url(b"{}"), _b64url(bytes(64))])


def _refused_as_base64(failure, reason):
    return failure is not None and failure.reason == reason and "base64" in failure.message.lower()


def _decode_receipt_data(verifier, text):
    failure = verifier.verify_receipt(text).failure
    if text == "":
        # Nothing to decode: the module refuses the empty receipt by name,
        # before it reaches the decoder ("each port refuses it before decoding").
        return failure is not None and failure.reason == Reason.MALFORMED
    return _refused_as_base64(failure, Reason.MALFORMED)


def _decode_x5c(verifier, text):
    failure = verifier.verify_signed_data(_jws_with_x5c(text)).failure
    return _refused_as_base64(failure, Reason.INVALID_CERTIFICATE)


BASE64_DECODERS = {"receipt-data": _decode_receipt_data, "x5c": _decode_x5c}


def decode_base64_failures(case):
    """Every text of the group that landed on the wrong side of the rule
    for a decoder the group names, by case id, decoder, index and repr of
    the text."""
    expected = case["expected"]
    texts = case["input"]["texts"]
    if not texts or not case["decoders"]:
        raise AssertionError(f"harness error: {case['id']}: no texts or no decoders")
    verifier = Verifier(Config())
    failures = []
    for name in case["decoders"]:
        refused_as_base64 = BASE64_DECODERS[name]
        for index, text in enumerate(texts):
            where = f"{case['id']}: {name} texts[{index}] {text!r}"
            refused = refused_as_base64(verifier, text)
            if expected["status"] == "ok" and refused:
                failures.append(f"{where} was refused as base64, want it decoded")
            elif expected["status"] == "error" and not refused:
                failures.append(f"{where} was not refused as base64")
    return failures


# --- result normalization ----------------------------------------------

MISSING = object()


def _iso_utc(value):
    from datetime import timezone

    text = value.astimezone(timezone.utc).isoformat()
    return text.replace("+00:00", "Z")


def normalize_receipt(payload):
    """A ReceiptPayload/InAppPurchase, normalized to its own canonical
    JSON, then re-parsed: the field paths in cases.json are written
    against that exact JSON shape (snake_case, *_ms epoch numbers, 64-bit
    ids as strings)."""
    return json.loads(payload.to_json())


def normalize_jws(payload):
    return json.loads(payload.json)


def normalize_endpoint(response_json):
    return json.loads(response_json)


# --- field paths --------------------------------------------------------

# A path step is a JSON Pointer (RFC 6901) reference token, "/name" or
# "/0", or this schema's extension, "/[key=value]", selecting the single
# array element whose member equals value. The bracket form's own "/" is
# part of the bracket token, so it must be tried before the plain-name
# alternative or that would consume the "/" on its own with an empty name.
PATH_STEP = re.compile(r"/\[([^\]]+)\]|/([^/\[\]]*)")


def path_steps(path):
    if path == "":
        return []
    steps = []
    consumed = 0
    for match in PATH_STEP.finditer(path):
        if match.start() != consumed:
            raise AssertionError(f"harness error: unparseable field path {path!r}")
        consumed = match.end()
        bracket, name = match.group(1), match.group(2)
        steps.append((bracket is not None, bracket if bracket is not None else name))
    if consumed != len(path):
        raise AssertionError(f"harness error: unparseable field path {path!r}")
    return steps


def resolve_path(root, path):
    current = root
    for is_bracket, step in path_steps(path):
        if current is None or current is MISSING:
            return MISSING
        if not is_bracket:
            if step == "length" and isinstance(current, list):
                current = len(current)
            elif isinstance(current, list):
                index = int(step)
                current = current[index] if 0 <= index < len(current) else MISSING
            elif isinstance(current, dict):
                current = current.get(step, MISSING)
            else:
                return MISSING
            continue
        key, separator, wanted = step.partition("=")
        if separator:
            if not isinstance(current, list):
                raise AssertionError(f"{path}: [{step}] does not select from a list")
            matches = [e for e in current if isinstance(e, dict) and e.get(key) == wanted]
            if len(matches) != 1:
                raise AssertionError(
                    f"{path}: [{step}] must select exactly one element, selected {len(matches)}"
                )
            current = matches[0]
        elif isinstance(current, list):
            index = int(step)
            current = current[index] if index < len(current) else MISSING
        elif isinstance(current, dict):
            current = current.get(step, MISSING)
        else:
            return MISSING
    return current


def resolve_length(root, path):
    value = resolve_path(root, path)
    return len(value) if isinstance(value, list) else MISSING


# --- one case -----------------------------------------------------------


class ConformanceCasesTest(unittest.TestCase):
    """One test method per case in fixtures/cases.json (generated below)."""

    def run_case(self, case):
        RAN.add(case["id"])
        if case["operation"] == "decodeBase64":
            failures = decode_base64_failures(case)
            self.assertEqual([], failures, "\n".join(failures))
            return
        operation = OPERATIONS.get(case["operation"])
        if operation is None:
            raise AssertionError(f"harness error: no adapter for operation {case['operation']!r}")
        request_body = case["input"].get("requestBody")
        if request_body is not None:
            data = fixture_bytes(request_body)
            codec = "requestBody"
        else:
            fixture_id = case["input"]["fixture"]
            data = fixture_bytes(fixture_id)
            codec = CASES["fixtures"][fixture_id]["codec"]

        max_millis = case.get("maxMillis")
        if max_millis is not None:
            operation(case, data, codec)  # warm-up call, unmeasured
        started = time.monotonic()
        result = operation(case, data, codec)
        elapsed_ms = (time.monotonic() - started) * 1000
        if max_millis is not None:
            self.assertLessEqual(
                elapsed_ms,
                max_millis,
                f"{case['id']}: took {elapsed_ms:.1f} ms, budget {max_millis} ms",
            )

        expected = case["expected"]
        if "oneOf" in expected:
            # Port-defined within a list; reaching this line proves no crash.
            outcome = "ok" if result.verified else result.failure.reason.name
            self.assertIn(outcome, expected["oneOf"], f"{case['id']}: answered {outcome}")
            return
        if case["operation"] == "verifyReceiptEndpoint":
            actual = normalize_endpoint(result)
            self._assert_fields(case, actual, expected)
            return

        if not result.verified:
            failure = result.failure
            self.assertEqual(
                expected["status"],
                "error",
                f"{case['id']}: expected success but got {failure.reason}",
            )
            self.assertEqual(failure.reason.name, expected["reason"], f"{case['id']}: reason")
            for code_point in expected.get("messageMustNotContain", []):
                where = f"{case['id']}: message must not contain U+{code_point:04X}"
                self.assertNotIn(chr(code_point), failure.message, f"{where}: {failure.message!r}")
            return

        self.assertEqual(
            expected["status"],
            "ok",
            f"{case['id']}: expected {expected.get('reason')} but verified",
        )
        payload = result.payload
        if case["operation"] == "verifyReceipt":
            actual = normalize_receipt(payload)
            if "toJson" in expected:
                # Same value, not same bytes (docs/design/0.7-api.md).
                # Re-encoding both sides with sorted keys ignores key order
                # and escaping but, unlike ==, tells true from 1.
                self.assertEqual(
                    json.dumps(json.loads(payload.to_json()), sort_keys=True),
                    json.dumps(json.loads(expected["toJson"]), sort_keys=True),
                    f"{case['id']}: toJson",
                )
        else:
            actual = normalize_jws(payload)
        self._assert_fields(case, actual, expected)

    def _assert_fields(self, case, actual, expected):
        for path, want in expected.get("fields", {}).items():
            got = resolve_path(actual, path)
            if want is None:
                self.assertIn(
                    got, (None, MISSING), f"{case['id']}: {path}: expected absent, got {got!r}"
                )
            else:
                self.assertEqual(got, want, f"{case['id']}: {path}")
        for path, want in expected.get("lengths", {}).items():
            got = resolve_length(actual, path)
            self.assertEqual(got, want, f"{case['id']}: length of {path}")


class FixtureRegistryTest(unittest.TestCase):
    """``fixture_bytes`` checks the digest of every fixture a case actually
    reads. This sweeps the rest: a fixture registered but referenced by no
    case still has to match, or the drift is only caught by whichever port
    happens to add the first vector for it."""

    def test_every_registered_fixture_matches_its_recorded_digest(self):
        registry = CASES["fixtures"]
        self.assertTrue(registry)
        for fixture_id in registry:
            with self.subTest(fixture_id):
                fixture_bytes(fixture_id)  # raises on a digest mismatch


# Which case ids actually ran, so the coverage check in tearDownModule is a
# fact rather than a loop-shaped assumption.
RAN: "set[str]" = set()


def _test_filter():
    for arg in sys.argv[1:]:
        if arg.startswith("-k") or re.search(r"test_conformance\.\w", arg):
            return arg
    return None


def _method_name(case_id):
    return "test_" + re.sub(r"[^0-9a-z]+", "_", case_id)


def _make_test(case):
    def test(self):
        self.run_case(case)

    return test


for _case in CASES["cases"]:
    setattr(ConformanceCasesTest, _method_name(_case["id"]), _make_test(_case))


def setUpModule():
    clocked = [c["id"] for c in CASES["cases"] if "clock" in c]
    print(
        f"conformance (0.7): {len(CASES['cases'])} cases, 0 skipped; "
        f"{len(clocked)} run against an injected clock"
    )


def tearDownModule():
    selector = _test_filter()
    if selector is not None:
        print(f"conformance: {selector!r} filters tests; the coverage self-check needs a full run")
        return
    missing = [c["id"] for c in CASES["cases"] if c["id"] not in RAN]
    if missing:
        raise AssertionError(
            f"{len(missing)} of {len(CASES['cases'])} cases did not run: {', '.join(missing)}"
        )


if __name__ == "__main__":
    unittest.main()
