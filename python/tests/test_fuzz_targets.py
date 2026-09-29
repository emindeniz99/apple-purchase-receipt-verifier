"""The fuzz targets (fuzz/targets) run without atheris: each seed directory
its ``run.sh`` uses, plus a fixed set of mutations of each seed, goes through
the target's ``one_input``. atheris publishes wheels only for 3.12 to 3.14, so
this is what keeps the targets compiling against the package, and their
invariants holding, on every line of the CI matrix. A stub stands in for the
``atheris`` module; the targets and the harness run unchanged."""

import contextlib
import importlib.util
import random
import sys
import unittest
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType
from unittest import mock

from _support import FIXTURES

FUZZ = Path(__file__).resolve().parents[1] / "fuzz"
MAX_SEED_BYTES = 300_000
MUTATIONS = 4

SEEDS = {
    "receipt_base64": [
        FIXTURES / "generated" / "receipt-b64",
        FIXTURES / "public-receipts",
        FIXTURES / "apple-official" / "xcode",
    ],
    "jws": [
        FIXTURES / "generated",
        FIXTURES / "apple-official" / "mock_signed_data",
        FIXTURES / "apple-official" / "xcode",
    ],
    "endpoint_json": [FUZZ / "seeds" / "endpoint-json"],
}


def stub_atheris() -> ModuleType:
    stub = ModuleType("atheris")
    stub.instrument_imports = contextlib.nullcontext  # type: ignore[attr-defined]
    stub.Setup = lambda *args, **kwargs: None  # type: ignore[attr-defined]
    stub.Fuzz = lambda: None  # type: ignore[attr-defined]
    return stub


@contextlib.contextmanager
def loaded_targets() -> "Iterator[dict[str, Callable[[bytes], object]]]":
    """The targets' ``one_input`` functions, imported the way ``run.sh``
    does: the fuzz directory on the path, ``harness`` first."""
    with mock.patch.dict(sys.modules, {"atheris": stub_atheris()}):
        sys.path.insert(0, str(FUZZ))
        try:
            found = {}
            for name in SEEDS:
                spec = importlib.util.spec_from_file_location(
                    f"fuzz_target_{name}", FUZZ / "targets" / f"{name}.py"
                )
                assert spec is not None and spec.loader is not None
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                found[name] = module.one_input
            yield found
        finally:
            sys.path.remove(str(FUZZ))
            sys.modules.pop("harness", None)


def seeds_of(directories: "list[Path]") -> "list[bytes]":
    out = []
    for directory in directories:
        for path in sorted(directory.iterdir()):
            if path.is_file() and path.stat().st_size <= MAX_SEED_BYTES:
                out.append(path.read_bytes())
    return out


def mutations(seed: bytes, rng: random.Random) -> "list[bytes]":
    out = [seed[: len(seed) // 2], seed + b"\x00"]
    for _ in range(MUTATIONS):
        data = bytearray(seed)
        for _ in range(3):
            if data:
                data[rng.randrange(len(data))] = rng.randrange(256)
        out.append(bytes(data))
    return out


class FuzzTargetsTest(unittest.TestCase):
    def test_every_target_holds_its_invariants_over_its_seeds_and_their_mutations(self) -> None:
        rng = random.Random(20260929)
        with loaded_targets() as targets:
            for name, directories in SEEDS.items():
                seeds = seeds_of(directories)
                self.assertGreater(len(seeds), 3, f"{name}: too few seeds ({directories})")
                inputs = [*seeds, *(m for seed in seeds for m in mutations(seed, rng))]
                with self.subTest(target=name, inputs=len(inputs)):
                    for data in inputs:
                        targets[name](data)  # raises InvariantViolation on a broken invariant

    def test_a_broken_invariant_is_reported(self) -> None:
        # The targets are only worth running if they can fail: an escape from
        # the public API must surface as InvariantViolation.
        with loaded_targets() as targets:
            harness = sys.modules["harness"]
            boom = mock.Mock(side_effect=TypeError("escaped"))
            with (
                mock.patch.object(harness.Verifier, "verify_receipt", boom),
                self.assertRaises(harness.InvariantViolation),
            ):
                targets["receipt_base64"](b"AAAA")


if __name__ == "__main__":
    unittest.main()
