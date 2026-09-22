"""The strict fast path in front of the receipt-data base64 decoder.

``decode_receipt_base64`` tries the stdlib's validating decoder first and
falls back to the tolerant rule on anything it declines. That is only a
speed-up if it can never change an answer: every string the fast path
accepts must be one the tolerant path accepts, with the same bytes, and every
rejection must still carry the tolerant path's reason and message. A client
whose receipt was refused yesterday must be refused today for the same
stated reason, and a receipt that decoded must decode to the same DER.
"""

import base64
import random
import string
import sys
import unittest
from collections.abc import Callable

from apple_purchase_receipt_verifier._receipt_base64 import (
    _decode_strict,
    _decode_tolerant,
    decode_receipt_base64,
)
from apple_purchase_receipt_verifier.exceptions import VerificationError

SEED = 20260922
RANDOM_INPUTS = 20_000

#: Strings where a validating decoder and the tolerant rule are most likely
#: to disagree: padding in every wrong count and place, whitespace, the other
#: alphabet, non-ASCII, and the lengths base64 cannot have.
EDGE_CASES = [
    "",
    " ",
    "\n",
    "=",
    "==",
    "===",
    "====",
    "A",
    "AA",
    "AAA",
    "AAAA",
    "A===",
    "AA=",
    "AA==",
    "AA===",
    "AAA=",
    "AAA==",
    "AAAA=",
    "AAAA==",
    "AAAA===",
    "AAAA====",
    "AAAAA===",
    "AB==",
    "AAB=",
    "QQ==QQ==",
    "AA==AA==",
    "AAA=AAA=",
    "AAAA\n",
    " AAAA",
    "AA\r\nAA",
    "AA-_",
    "AA+/",
    "A+_A",
    "AAAA!",
    "éééé",
    "AA\x00A",
    "////",
    "++++",
]

_WHITESPACE = " \t\r\n"
_POOL = string.ascii_letters + string.digits + "+/-_=" + _WHITESPACE + "!é"


def random_input(rng: random.Random) -> str:
    """One input, drawn so that each branch of the decoder gets thousands of
    hits: clean canonical base64, the variants only the tolerant path accepts,
    and near misses that both must reject."""
    raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
    canonical = base64.b64encode(raw).decode("ascii")
    kind = rng.randrange(6)
    if kind == 0:
        return canonical
    if kind == 1:
        urlsafe = canonical.replace("+", "-").replace("/", "_")
        return urlsafe.rstrip("=") if rng.random() < 0.5 else urlsafe
    if kind == 2:
        chars = list(canonical)
        for _ in range(rng.randrange(1, 4)):
            chars.insert(rng.randrange(len(chars) + 1), rng.choice(_WHITESPACE))
        return "".join(chars)
    if kind == 3:
        return canonical.rstrip("=") + "=" * rng.randrange(5)
    if kind == 4:
        chars = list(canonical)
        position = rng.randrange(len(chars) + 1)
        operation = rng.randrange(3)
        if operation == 0 or not chars:
            chars.insert(position, rng.choice(_POOL))
        elif operation == 1:
            chars[min(position, len(chars) - 1)] = rng.choice(_POOL)
        else:
            del chars[min(position, len(chars) - 1)]
        return "".join(chars)
    return "".join(rng.choice(_POOL) for _ in range(rng.randrange(13)))


Outcome = tuple[str, object, object]


def outcome(decode: Callable[[str], bytes], text: str) -> Outcome:
    try:
        return ("ok", decode(text), None)
    except VerificationError as error:
        return ("error", error.reason, str(error))


def inputs() -> list[str]:
    rng = random.Random(SEED)
    return EDGE_CASES + [random_input(rng) for _ in range(RANDOM_INPUTS)]


def mismatches(fast: Callable[[str], bytes | None], texts: list[str]) -> list[str]:
    """The inputs on which ``fast`` in front of the tolerant path answers
    differently from the tolerant path alone."""

    def combined(text: str) -> bytes:
        decoded = fast(text)
        return decoded if decoded is not None else _decode_tolerant(text)

    return [text for text in texts if outcome(combined, text) != outcome(_decode_tolerant, text)]


class StrictFastPathTest(unittest.TestCase):
    def test_the_fast_path_never_changes_an_answer(self) -> None:
        texts = inputs()
        branches = {"fast path": 0, "tolerant accept": 0, "reject": 0}
        for text in texts:
            expected = outcome(_decode_tolerant, text)
            self.assertEqual(expected, outcome(decode_receipt_base64, text), repr(text))
            if _decode_strict(text) is not None:
                # Accepted by the fast path, so the tolerant path must accept
                # it too; the equality above already compared the bytes.
                self.assertEqual("ok", expected[0], repr(text))
                branches["fast path"] += 1
            elif expected[0] == "ok":
                branches["tolerant accept"] += 1
            else:
                branches["reject"] += 1
        # A differential test that never reached one of the branches proves
        # nothing about it.
        for branch, hits in branches.items():
            self.assertGreater(hits, 1000, f"{branch}: {branches}")

    def test_a_permissive_fast_path_is_caught(self) -> None:
        # The comparison above can fail: a decoder that skips characters
        # outside the alphabet instead of refusing them accepts strings the
        # tolerant rule rejects, and the same inputs expose it.
        def permissive(text: str) -> bytes | None:
            try:
                return base64.b64decode(text + "=" * (-len(text) % 4))
            except ValueError:
                return None

        self.assertTrue(mismatches(permissive, inputs()))

    def test_the_length_and_padding_guard_is_what_makes_the_decoder_a_subset(self) -> None:
        # b64decode(validate=True) with no guard in front accepts "AAAA=",
        # "AAA==" or "AAAA====" on the Pythons before 3.13, strings the
        # tolerant rule rejects. The guard is what keeps the fast path a
        # subset on the whole supported range, not the decoder alone.
        def unguarded(text: str) -> bytes | None:
            if not text:
                return None
            try:
                return base64.b64decode(text, validate=True)
            except ValueError:
                return None

        found = mismatches(unguarded, EDGE_CASES)
        self.assertEqual(sys.version_info < (3, 13), bool(found), found)
        self.assertEqual([], mismatches(_decode_strict, EDGE_CASES))


if __name__ == "__main__":
    unittest.main()
