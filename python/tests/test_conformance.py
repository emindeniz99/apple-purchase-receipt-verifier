"""Runs fixtures/cases.json — the normative cross-language conformance
vectors — against this implementation. The adapter below knows nothing about
any individual case: it loads the file, resolves fixture ids to bytes, builds
a verifier from the generic config, dispatches on "operation", normalizes the
result and reads the reason off a failure. A vector that disagrees with the
library is a bug report against one of the two; it is never something to
special-case here."""

import base64
import json
import re
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509

from apple_purchase_receipt_verifier import (
    JwsVerifier,
    ReceiptVerifier,
    VerificationError,
    VerifyReceiptEndpoint,
    apple_jws_roots,
    apple_receipt_roots,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
CASES = json.loads((FIXTURES / "cases.json").read_text())


def case_clock(case):
    """The ``clock.now`` of a case as this library's clock: a zero-argument
    callable returning epoch seconds. None for a case that pins no time, in
    which case the verifier falls back to the system clock."""
    clock = case.get("clock")
    if clock is None:
        return None
    moment = datetime.fromisoformat(clock["now"].replace("Z", "+00:00"))
    return lambda: moment.timestamp()


def fixture_bytes(fixture_id):
    """Decodes a registered fixture to its logical bytes (fixture.codec)."""
    entry = CASES["fixtures"].get(fixture_id)
    if entry is None:
        raise AssertionError(f"harness error: cases.json registers no fixture {fixture_id!r}")
    raw = (FIXTURES / entry["path"]).read_bytes()
    codec = entry["codec"]
    if codec == "raw":
        return raw
    if codec == "base64":
        return base64.b64decode(re.sub(r"\s+", "", raw.decode("ascii")))
    if codec == "utf8":
        return raw.decode("utf-8").strip().encode("utf-8")
    raise AssertionError(f"harness error: unknown fixture codec {codec!r}")


BUILTIN_ROOTS = {
    "apple-jws-roots": apple_jws_roots,
    "apple-receipt-roots": apple_receipt_roots,
}


def trusted_roots(spec):
    if spec["source"] == "builtin":
        roots = BUILTIN_ROOTS.get(spec["name"])
        if roots is None:
            raise AssertionError(f"harness error: unknown builtin root set {spec['name']!r}")
        return roots()
    return [x509.load_der_x509_certificate(fixture_bytes(i)) for i in spec["fixtures"]]


# verifyRaw enforces no claim, so its cases may omit bundleId and
# acceptedEnvironments — but the constructor still demands both. These
# placeholders match nothing the fixtures carry, so a claim check that leaked
# into verify_raw would surface as a failure, not as a pass.
UNMATCHABLE_BUNDLE_ID = "conformance.unset.bundle.id"
UNMATCHABLE_ENVIRONMENTS = ["LocalTesting"]


def jws_verifier(config, clock):
    max_age = config.get("maxSignedAgeSeconds")
    return JwsVerifier(
        trusted_roots=trusted_roots(config["trustedRoots"]),
        bundle_id=config.get("bundleId", UNMATCHABLE_BUNDLE_ID),
        accepted_environments=config.get("acceptedEnvironments", UNMATCHABLE_ENVIRONMENTS),
        app_apple_id=config.get("appAppleId"),
        max_signed_age_millis=None if max_age is None else max_age * 1000,
        clock=clock,
    )


def _receipt(config, data, clock):
    # ReceiptVerifier takes no clock: nothing on that path moves with the
    # current time (chain validity anchors at the receipt creation date).
    verifier = ReceiptVerifier(trusted_roots(config["trustedRoots"]), config["bundleId"])
    guid_hex = config.get("deviceGuidHex")
    return verifier.verify(data, None if guid_hex is None else bytes.fromhex(guid_hex))


OPERATIONS = {
    "verifyTransaction":
        lambda config, data, clock:
            jws_verifier(config, clock).verify_transaction(data.decode("utf-8")),
    "verifyAppTransaction":
        lambda config, data, clock:
            jws_verifier(config, clock).verify_app_transaction(data.decode("utf-8")),
    "verifyRaw":
        lambda config, data, clock:
            jws_verifier(config, clock).verify_raw(data.decode("utf-8")),
    "verifyReceipt": _receipt,
    "verifyReceiptEndpoint":
        lambda config, data, clock: VerifyReceiptEndpoint(
            trusted_roots(config["trustedRoots"]), config["environment"], clock,
        ).verify_receipt({"receipt-data": base64.b64encode(data).decode("ascii")}),
}


# --- result normalization ----------------------------------------------

MISSING = object()


def _camel(name):
    head, _, tail = name.partition("_")
    return head + "".join(word[:1].upper() + word[1:] for word in tail.split("_") if word)


def _iso_utc(value):
    text = value.astimezone(timezone.utc).isoformat()
    return text.replace("+00:00", "Z")


def normalize(value):
    """Renders a returned value into the language-neutral shape the field
    paths are written against: dates as ISO-8601 UTC, binary as lowercase hex
    (also under ``<name>Hex``, the spelling cases.json uses for a byte field),
    and the snake_case attributes of a result object under their shared
    camelCase names. Dict keys — the verifyReceipt endpoint's Apple wire
    keys — are left exactly as the library spells them."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return _iso_utc(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [normalize(v) for v in value]
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in value.items()}
    out = {}
    for key, attribute in vars(value).items():
        name = _camel(key)
        out[name] = normalize(attribute)
        if isinstance(attribute, (bytes, bytearray)):
            out[name + "Hex"] = out[name]
    return out


# --- field paths --------------------------------------------------------

# A path step is either a name (`bundleId`, `length`) or a bracket (`[9999]`,
# `[0]`, `[productId=com.example.app.vip]`). Bracket contents may hold dots,
# so the split cannot be a plain str.split(".").
PATH_STEP = re.compile(r"\.?([^.\[\]]+)|\[([^\]]+)\]")


def path_steps(path):
    steps = []
    consumed = 0
    for match in PATH_STEP.finditer(path):
        if match.start() != consumed:
            raise AssertionError(f"harness error: unparseable field path {path!r}")
        consumed = match.end()
        name, bracket = match.group(1), match.group(2)
        steps.append((name is None, name if bracket is None else bracket))
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
                    f"{path}: [{step}] must select exactly one element, selected {len(matches)}")
            current = matches[0]
        elif isinstance(current, list):
            index = int(step)
            current = current[index] if index < len(current) else MISSING
        elif isinstance(current, dict):
            current = current.get(step, MISSING)
        else:
            return MISSING
    return current


# --- one case -----------------------------------------------------------

class ConformanceCasesTest(unittest.TestCase):
    """One test method per case in fixtures/cases.json — generated below."""

    def run_case(self, case):
        operation = OPERATIONS.get(case["operation"])
        if operation is None:
            raise AssertionError(
                f"harness error: no adapter for operation {case['operation']!r}")
        data = fixture_bytes(case["input"]["fixture"])
        expected = case["expected"]
        try:
            result = operation(case["config"], data, case_clock(case))
        except VerificationError as e:
            # Only a VerificationError carries a canonical Reason.
            self.assertEqual(expected["status"], "error",
                             f"{case['id']}: expected success but raised {e.reason}")
            self.assertEqual(e.reason, expected["reason"], f"{case['id']}: reason")
            return
        except Exception as e:
            # Anything else is a defect in the library or in this harness, and
            # must never be read as one of the expected reasons.
            raise AssertionError(
                f"harness error: {case['id']}: {case['operation']} raised "
                f"{type(e).__name__} ({e}), which is not a VerificationError") from e
        self.assertEqual(
            expected["status"], "ok",
            f"{case['id']}: expected {expected.get('reason')} but the call returned a value")
        actual = normalize(result)
        for path, want in expected["fields"].items():
            got = resolve_path(actual, path)
            if want is None:
                # null means "absent or unset".
                self.assertIn(got, (None, MISSING),
                              f"{case['id']}: {path}: expected absent, got {got!r}")
            else:
                self.assertEqual(got, want, f"{case['id']}: {path}")


def _method_name(case_id):
    return "test_" + re.sub(r"[^0-9a-z]+", "_", case_id)


for _case in CASES["cases"]:
    setattr(ConformanceCasesTest, _method_name(_case["id"]),
            (lambda case: lambda self: self.run_case(case))(_case))


def setUpModule():
    clocked = [c["id"] for c in CASES["cases"] if "clock" in c]
    print(f"conformance: {len(CASES['cases'])} cases, 0 skipped; "
          f"{len(clocked)} run against an injected clock {clocked}")


if __name__ == "__main__":
    unittest.main()
