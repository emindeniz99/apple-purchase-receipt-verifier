"""R28: on a platform wasmtime-py ships no wheel for, installing stops with a
pointer to aprv-server and the C ABI, instead of ``import`` failing later.

Three layers: the platform table (every wheel tag R12 planned), the
``setup.py`` hook that refuses a wheel build for or on an unsupported
platform (run on a copy of the source tree, so the tree stays clean), and the
release's file check (no ``py3-none-any`` wheel may be published, or pip would
install on the platforms this refuses). The pip-level proof, with a faked
platform and the sdist as the only candidate, is the install-failure leg in
CI-NOTES.md."""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

import _wheel_platform as platforms  # noqa: E402
from apple_purchase_receipt_verifier.version import CURRENT as VERSION  # noqa: E402

#: The 19 wheel tags docs/rust-core planned (R12), and what wasmtime-py 49.0.0
#: ships for them (docs/evidence/2026-09-26-python-wasmtime.md).
PLANNED = {
    "manylinux2014_x86_64": True,
    "manylinux2014_aarch64": True,
    "musllinux_1_2_x86_64": True,
    "musllinux_1_2_aarch64": True,
    "macosx_10_13_x86_64": True,
    "macosx_11_0_arm64": True,
    "win_amd64": True,
    "win_arm64": True,
    "manylinux2014_armv7l": False,
    "manylinux2014_i686": False,
    "manylinux2014_ppc64le": False,
    "manylinux2014_s390x": False,
    "manylinux2014_riscv64": False,
    "linux_armv6l": False,
    "musllinux_1_2_armv7l": False,
    "musllinux_1_2_i686": False,
    "musllinux_1_2_ppc64le": False,
    "musllinux_1_2_riscv64": False,
    "win32": False,
}


def has_setuptools() -> bool:
    return importlib.util.find_spec("setuptools") is not None


class PlatformTableTest(unittest.TestCase):
    def test_the_planned_tags_split_as_wasmtime_py_ships_them(self) -> None:
        self.assertEqual(19, len(PLANNED))
        self.assertEqual(8, sum(PLANNED.values()))
        for tag, supported in PLANNED.items():
            with self.subTest(tag=tag):
                self.assertEqual(supported, platforms.is_supported(tag))
                self.assertEqual(supported, platforms.unsupported_message(tag) is None)

    def test_the_distutils_spellings_of_the_same_platforms_agree(self) -> None:
        # What sysconfig.get_platform() reports, which is what pip derives
        # its own wheel tags from.
        for platform, supported in {
            "linux-x86_64": True,
            "linux-aarch64": True,
            "linux-i686": False,
            "linux-armv7l": False,
            "linux-armv8l": False,  # a 32-bit interpreter on an aarch64 kernel
            "linux-ppc64le": False,
            "linux-s390x": False,
            "linux-riscv64": False,
            "macosx-10.13-x86_64": True,
            "macosx-11.0-arm64": True,
            "macosx-14.0-arm64": True,
            "macosx-10.9-universal2": True,
            "macosx-10.6-i386": False,
            "win-amd64": True,
            "win-arm64": True,
            "win32": False,
            "android-26-arm64_v8a": True,
            "android-21-x86_64": True,
            "android-24-armeabi_v7a": False,
            "freebsd-14.0-RELEASE-amd64": False,
            "solaris-2.11-sun4v": False,
            "emscripten-3.1.58-wasm32": False,
        }.items():
            with self.subTest(platform=platform):
                self.assertEqual(supported, platforms.is_supported(platform))

    def test_the_wheels_the_release_builds_are_exactly_the_supported_ones(self) -> None:
        self.assertEqual({t for t, ok in PLANNED.items() if ok}, set(platforms.WHEEL_TAGS))
        for tag in platforms.WHEEL_TAGS:
            self.assertTrue(platforms.is_supported(tag), tag)

    def test_the_message_says_what_to_use_instead(self) -> None:
        message = platforms.unsupported_message("linux-i686") or ""
        self.assertIn("linux-i686", message)
        self.assertIn("aprv-server", message)
        self.assertIn("C ABI", message)
        self.assertIn("wasmtime", message)


def copy_source(destination: Path) -> None:
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    for name in ("setup.py", "_wheel_platform.py", "pyproject.toml", "MANIFEST.in", "LICENSE"):
        shutil.copy(PROJECT / name, destination / name)
    shutil.copy(PROJECT / "README.md", destination / "README.md")
    shutil.copytree(
        PROJECT / "apple_purchase_receipt_verifier",
        destination / "apple_purchase_receipt_verifier",
        ignore=ignore,
    )


@unittest.skipUnless(has_setuptools(), "the setup.py hook needs setuptools (the dev extra has it)")
class SetupHookTest(unittest.TestCase):
    """``setup.py bdist_wheel`` on a copy of the tree, as pip and build run it."""

    holder: "tempfile.TemporaryDirectory[str]"
    source: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.holder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.holder.cleanup)
        cls.source = Path(cls.holder.name) / "source"
        cls.source.mkdir()
        copy_source(cls.source)

    def build(self, *args: str, host: "str | None" = None) -> "tuple[int, str, list[str]]":
        out = Path(tempfile.mkdtemp(dir=self.holder.name))
        environment = {k: v for k, v in os.environ.items() if k != "_PYTHON_HOST_PLATFORM"}
        if host is not None:
            environment["_PYTHON_HOST_PLATFORM"] = host
        done = subprocess.run(
            [sys.executable, "setup.py", "-q", "bdist_wheel", *args, "-d", str(out)],
            cwd=self.source,
            env=environment,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        return done.returncode, done.stdout + done.stderr, sorted(p.name for p in out.iterdir())

    def test_a_wheel_for_an_unsupported_platform_is_refused_with_the_pointer(self) -> None:
        for tag in ("manylinux2014_i686", "manylinux2014_ppc64le", "win32", "linux_armv6l"):
            with self.subTest(plat_name=tag):
                code, output, wheels = self.build("--plat-name", tag)
                self.assertNotEqual(0, code)
                self.assertEqual([], wheels)
                self.assertIn("aprv-server", output)
                self.assertIn("C ABI", output)

    def test_building_on_an_unsupported_platform_is_refused_with_the_pointer(self) -> None:
        # No --plat-name: the build machine's own platform decides, which is
        # what pip building the sdist on that machine sees.
        for host in ("linux-i686", "linux-s390x", "linux-armv7l", "win32"):
            with self.subTest(host=host):
                code, output, wheels = self.build(host=host)
                self.assertNotEqual(0, code)
                self.assertEqual([], wheels)
                self.assertIn("aprv-server", output)
                self.assertIn(host, output)

    def test_a_supported_platform_builds_a_pure_wheel_tagged_for_it(self) -> None:
        for tag in platforms.WHEEL_TAGS:
            with self.subTest(plat_name=tag):
                code, output, wheels = self.build("--plat-name", tag)
                self.assertEqual(0, code, output)
                self.assertEqual(
                    [f"apple_purchase_receipt_verifier-{VERSION}-py3-none-{tag}.whl"], wheels
                )

    def test_a_build_on_the_supported_platform_it_runs_on_still_works(self) -> None:
        code, output, wheels = self.build(host="linux-x86_64")
        self.assertEqual(0, code, output)
        self.assertEqual([f"apple_purchase_receipt_verifier-{VERSION}-py3-none-any.whl"], wheels)


def load_build_dist() -> "object":
    spec = importlib.util.spec_from_file_location("build_dist", PROJECT / "tools" / "build_dist.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseFilesTest(unittest.TestCase):
    def files(self, names: "list[str]") -> Path:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        for name in names:
            (Path(holder.name) / name).write_bytes(b"")
        return Path(holder.name)

    def complete(self, version: str = "0.8.0") -> "list[str]":
        module = load_build_dist()
        return sorted(module.expected_names(version))  # type: ignore[attr-defined]

    def problems(self, names: "list[str]") -> "list[str]":
        module = load_build_dist()
        return module.check(self.files(names))  # type: ignore[attr-defined, no-any-return]

    def test_the_sdist_and_one_wheel_per_supported_platform_pass(self) -> None:
        names = self.complete()
        self.assertEqual(1 + len(platforms.WHEEL_TAGS), len(names))
        self.assertEqual([], self.problems(names))

    def test_a_py3_none_any_wheel_is_refused(self) -> None:
        names = [*self.complete(), "apple_purchase_receipt_verifier-0.8.0-py3-none-any.whl"]
        problems = self.problems(names)
        self.assertEqual(1, len(problems), problems)
        self.assertIn("py3-none-any", problems[0])

    def test_a_missing_platform_wheel_is_refused(self) -> None:
        names = [n for n in self.complete() if "win_arm64" not in n]
        self.assertEqual(
            ["missing apple_purchase_receipt_verifier-0.8.0-py3-none-win_arm64.whl"],
            self.problems(names),
        )

    def test_no_sdist_is_refused(self) -> None:
        names = [n for n in self.complete() if not n.endswith(".tar.gz")]
        self.assertEqual(1, len(self.problems(names)))


if __name__ == "__main__":
    unittest.main()
