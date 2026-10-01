"""Wasmtime's compile cache under THREAT-MODEL.md section 8: on by default in
the user's own cache directory, ``APRV_WASM_CACHE_DIR`` overrides the path,
and a directory that is read-only, foreign-owned, or writable by anyone else
turns the cache off silently: the process compiles at start and still
verifies. The end-to-end cases run a fresh interpreter, because the compiled
module is one per process."""

import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from apple_purchase_receipt_verifier import _cache

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
POSIX = hasattr(os, "geteuid")
ROOT_USER = POSIX and os.geteuid() == 0

CHILD = """
import json, os, time
{prelude}
started = time.perf_counter()
from apple_purchase_receipt_verifier import Config, Verifier
import pathlib
receipt = "".join(pathlib.Path({receipt!r}).read_text().split())
verifier = Verifier(Config())
created = time.perf_counter() - started
verified = verifier.verify_receipt(receipt).verified
print(json.dumps({{"verified": verified, "seconds": created}}))
"""


def cache_entries(directory: Path) -> int:
    modules = directory / "modules"
    return sum(1 for _ in modules.rglob("*") if _.is_file()) if modules.is_dir() else 0


def module_entries(directory: Path) -> "dict[str, tuple[int, int]]":
    """The compiled modules the cache holds: name to (size, mtime in ns).

    Wasmtime keeps bookkeeping beside each module, written by a background
    thread after the process's own work: ``<name>.stats``, and while it
    updates that a ``<name>.tmp-atomic-write-stats`` file that a process can
    exit in the middle of. Neither says whether anything was compiled, and
    counting them made the test depend on that race. A module entry is a
    file whose name is the key alone (no dot), stored by an atomic
    rename: a process that compiled and stored again would replace the file
    (a new mtime) or add another key.
    """
    found: dict[str, tuple[int, int]] = {}
    modules = directory / "modules"
    for path in modules.rglob("*") if modules.is_dir() else ():
        if path.is_file() and "." not in path.name:
            info = path.stat()
            found[str(path.relative_to(modules))] = (info.st_size, info.st_mtime_ns)
    return found


def run_child(env: "dict[str, str]", prelude: str = "") -> "dict[str, object]":
    receipt = PACKAGE_ROOT.parent / "fixtures" / "public-receipts" / "receipt-sandbox-g5.b64"
    code = CHILD.format(prelude=textwrap.dedent(prelude), receipt=str(receipt))
    environment = {k: v for k, v in os.environ.items() if k != _cache.ENV_VAR}
    environment.update(env)
    environment["PYTHONPATH"] = os.pathsep.join(
        [str(PACKAGE_ROOT), environment.get("PYTHONPATH", "")]
    )
    done = subprocess.run(
        [sys.executable, "-c", code],
        env=environment,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if done.returncode != 0:
        raise AssertionError(f"child failed: {done.stderr}")
    return json.loads(done.stdout.strip().splitlines()[-1])  # type: ignore[no-any-return]


class Sandbox(unittest.TestCase):
    def directory(self, mode: int = 0o700) -> Path:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        path = Path(holder.name) / "cache"
        path.mkdir(mode=mode)
        path.chmod(mode)
        return path


class RulesTest(Sandbox):
    """``usable_directory`` on its own: which directories the cache may use."""

    def usable(self, path: "Path | str") -> "str | None":
        with mock.patch.dict(os.environ, {_cache.ENV_VAR: str(path)}):
            return _cache.usable_directory()

    def test_a_private_directory_of_the_user_is_usable(self) -> None:
        directory = self.directory()
        self.assertEqual(str(directory), self.usable(directory))

    def test_a_missing_directory_is_created_private(self) -> None:
        holder = self.directory()
        target = holder / "a" / "b"
        self.assertEqual(str(target), self.usable(target))
        self.assertTrue(target.is_dir())
        if POSIX:
            for made in (holder / "a", target):
                self.assertEqual(0, stat.S_IMODE(made.stat().st_mode) & 0o077, made)

    def test_an_empty_or_relative_path_turns_the_cache_off(self) -> None:
        self.assertIsNone(self.usable(""))
        self.assertIsNone(self.usable("relative/cache"))

    def test_a_path_that_cannot_be_created_turns_the_cache_off(self) -> None:
        directory = self.directory()
        blocker = directory / "file"
        blocker.write_text("x")
        self.assertIsNone(self.usable(blocker / "cache"))

    def test_a_read_only_directory_turns_the_cache_off(self) -> None:
        directory = self.directory()
        with mock.patch("os.access", return_value=False):
            self.assertIsNone(self.usable(directory))

    @unittest.skipUnless(
        POSIX, "Windows has no owner or mode bits to read; only the read-only rule applies"
    )
    def test_a_directory_writable_by_group_or_others_turns_the_cache_off(self) -> None:
        for mode in (0o770, 0o707, 0o777, 0o720):
            with self.subTest(mode=oct(mode)):
                directory = self.directory()
                directory.chmod(mode)
                self.assertIsNone(self.usable(directory))

    @unittest.skipUnless(POSIX, "Windows has no owner bits to read")
    def test_a_directory_the_user_does_not_own_turns_the_cache_off(self) -> None:
        directory = self.directory()
        with mock.patch("os.geteuid", return_value=os.geteuid() + 4242):
            self.assertIsNone(self.usable(directory))

    @unittest.skipUnless(POSIX, "Windows has no owner or mode bits to read")
    def test_a_directory_whose_parent_someone_else_can_swap_turns_the_cache_off(self) -> None:
        holder = self.directory()
        inner = holder / "cache"
        inner.mkdir(mode=0o700)
        holder.chmod(0o777)  # anyone may rename or replace "cache"
        self.assertIsNone(self.usable(inner))
        holder.chmod(0o700)
        self.assertEqual(str(inner), self.usable(inner))

    @unittest.skipUnless(POSIX, "Windows has no mode bits to read")
    def test_a_shared_sticky_directory_never_holds_the_cache_itself(self) -> None:
        with tempfile.TemporaryDirectory() as shared:
            os.chmod(shared, 0o1777)
            self.assertIsNone(self.usable(shared))

    def test_the_default_is_the_users_own_cache_directory(self) -> None:
        home = self.directory()
        env = {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CACHE_HOME": "",
            "LOCALAPPDATA": str(home),
        }
        with mock.patch.dict(os.environ, env):
            os.environ.pop(_cache.ENV_VAR, None)
            path = _cache.usable_directory()
        assert path is not None
        self.assertTrue(path.startswith(str(home)), path)
        self.assertTrue(path.endswith(os.path.join("apple-purchase-receipt-verifier", "wasmtime")))

    def test_the_toml_wasmtime_reads_is_written_privately_and_removed(self) -> None:
        import wasmtime

        directory = self.directory()
        with mock.patch.dict(os.environ, {_cache.ENV_VAR: str(directory)}):
            self.assertTrue(_cache.enable(wasmtime.Config()))
        self.assertEqual([], [p for p in directory.iterdir() if p.suffix == ".toml"])

    def test_a_path_toml_cannot_carry_is_off_not_an_error(self) -> None:
        import wasmtime

        holder = self.directory()
        quoted = holder / "it's"
        with mock.patch.dict(os.environ, {_cache.ENV_VAR: str(quoted)}):
            self.assertFalse(_cache.enable(wasmtime.Config()))


class EndToEndTest(Sandbox):
    """A fresh process per case: compile (or not), then verify a receipt."""

    def test_the_cache_fills_on_the_first_process_and_serves_the_second(self) -> None:
        directory = self.directory()
        env = {_cache.ENV_VAR: str(directory)}
        cold = run_child(env)
        self.assertTrue(cold["verified"])
        # run_child returns after the process exits, and the module is stored
        # by an atomic rename before the compile returns, so the entry is in
        # place before the second process starts.
        stored = module_entries(directory)
        self.assertEqual(1, len(stored), f"the first process should store the one module: {stored}")
        warm = run_child(env)
        self.assertTrue(warm["verified"])
        self.assertEqual(stored, module_entries(directory), "the second process compiled again")
        print(
            f"\ncold start {cold['seconds']:.3f} s, warm start {warm['seconds']:.3f} s",
            file=sys.stderr,
        )

    @unittest.skipUnless(POSIX, "a symbolic link needs no privilege here")
    def test_the_same_directory_by_another_path_serves_the_entry(self) -> None:
        """The key holds no path: a directory reached through a symbolic link
        (macOS's /var against /private/var) finds what the other path stored."""
        directory = self.directory()
        alias = directory.parent / "alias"
        alias.symlink_to(directory, target_is_directory=True)
        self.assertTrue(run_child({_cache.ENV_VAR: str(directory)})["verified"])
        stored = module_entries(directory)
        self.assertEqual(1, len(stored), stored)
        self.assertTrue(run_child({_cache.ENV_VAR: str(alias)})["verified"])
        self.assertEqual(stored, module_entries(directory), "the other path compiled again")

    def test_a_read_only_directory_still_verifies_and_holds_nothing(self) -> None:
        directory = self.directory()
        if ROOT_USER or not POSIX:
            # root writes through a 0500 directory, so the read-only answer
            # of the operating system is simulated where the package asks it.
            prelude = "import os; os.access = lambda *args, **kwargs: False"
            result = run_child({_cache.ENV_VAR: str(directory)}, prelude)
        else:
            directory.chmod(0o500)
            self.addCleanup(directory.chmod, 0o700)
            result = run_child({_cache.ENV_VAR: str(directory)})
        self.assertTrue(result["verified"])
        self.assertEqual(0, cache_entries(directory))

    @unittest.skipUnless(POSIX, "Windows has no owner bits to read")
    def test_a_foreign_owned_directory_still_verifies_and_holds_nothing(self) -> None:
        directory = self.directory()
        prelude = f"import os; os.geteuid = lambda: os.stat({str(directory)!r}).st_uid + 4242"
        result = run_child({_cache.ENV_VAR: str(directory)}, prelude)
        self.assertTrue(result["verified"])
        self.assertEqual(0, cache_entries(directory))

    @unittest.skipUnless(POSIX, "Windows has no mode bits to read")
    def test_a_directory_others_can_write_still_verifies_and_holds_nothing(self) -> None:
        directory = self.directory()
        directory.chmod(0o777)
        result = run_child({_cache.ENV_VAR: str(directory)})
        self.assertTrue(result["verified"])
        self.assertEqual(0, cache_entries(directory))

    def test_an_empty_variable_turns_the_cache_off(self) -> None:
        home = self.directory()
        env = {
            _cache.ENV_VAR: "",
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CACHE_HOME": str(home),
            "LOCALAPPDATA": str(home),
        }
        self.assertTrue(run_child(env)["verified"])
        self.assertEqual(
            [], list(home.iterdir()), "the cache was created despite the empty variable"
        )

    def test_with_no_variable_the_cache_lives_in_the_users_cache_directory(self) -> None:
        home = self.directory()
        env = {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CACHE_HOME": str(home / "xdg"),
            "LOCALAPPDATA": str(home / "local"),
        }
        self.assertTrue(run_child(env)["verified"])
        found = [p for p in home.rglob("modules") if p.is_dir()]
        self.assertEqual(1, len(found), [str(p) for p in home.rglob("*")][:20])
        self.assertIn("apple-purchase-receipt-verifier", found[0].parts)


if __name__ == "__main__":
    unittest.main()
