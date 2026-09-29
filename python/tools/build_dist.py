"""Builds, or checks, the files the release publishes to PyPI.

    python tools/build_dist.py [--out dist]    the sdist and one wheel per platform
    python tools/build_dist.py --check dist    fail unless dist holds exactly those

The package is pure Python, but it is published as one wheel per platform
wasmtime-py has a wheel for, and never as a ``py3-none-any`` wheel: on any
other platform pip then finds no wheel and builds the sdist, whose build
refuses the platform with a message that points to aprv-server and the C ABI
(``_wheel_platform.py``, docs/rust-core R28). A plain ``python -m build``
would publish the ``any`` wheel and quietly undo that, so the release job
uses this script, and its check step, instead. Needs the ``build`` package.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from _wheel_platform import WHEEL_TAGS  # noqa: E402

DISTRIBUTION = "apple_purchase_receipt_verifier"


def build(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    base = [sys.executable, "-m", "build", "--outdir", str(out)]
    subprocess.run([*base, "--sdist", str(PROJECT)], check=True)
    for tag in WHEEL_TAGS:
        subprocess.run(
            [*base, "--wheel", f"-C--build-option=--plat-name={tag}", str(PROJECT)], check=True
        )


def expected_names(version: str) -> "set[str]":
    names = {f"{DISTRIBUTION}-{version}.tar.gz"}
    names |= {f"{DISTRIBUTION}-{version}-py3-none-{tag}.whl" for tag in WHEEL_TAGS}
    return names


def check(directory: Path) -> "list[str]":
    """What is wrong with ``directory``, one message per problem."""
    found = {path.name for path in directory.iterdir() if path.is_file()}
    sdists = sorted(name for name in found if name.endswith(".tar.gz"))
    if len(sdists) != 1:
        return [f"expected exactly one sdist, found {sdists}"]
    match = re.fullmatch(rf"{DISTRIBUTION}-(.+)\.tar\.gz", sdists[0])
    if match is None:
        return [f"cannot read a version out of {sdists[0]}"]
    wanted = expected_names(match.group(1))
    problems = [f"missing {name}" for name in sorted(wanted - found)]
    problems += [
        f"unexpected {name}"
        + (" (a py3-none-any wheel undoes the install failure)" if "-any." in name else "")
        for name in sorted(found - wanted)
    ]
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=PROJECT / "dist")
    parser.add_argument("--check", type=Path, metavar="DIR")
    arguments = parser.parse_args()
    if arguments.check is not None:
        problems = check(arguments.check)
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0
    build(arguments.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
