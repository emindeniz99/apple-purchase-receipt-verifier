"""Wasmtime's compile cache under THREAT-MODEL.md section 8: on by default in
the user's own cache directory (the one ``platformdirs`` names for the
platform), ``APRV_WASM_CACHE_DIR`` overrides the path,
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
APP = "apple-purchase-receipt-verifier"
#: What decides the default directory besides HOME: a test sets each one it
#: needs and starts from none of the caller's.
LOCATION_VARIABLES = ("XDG_CACHE_HOME", "WIN_PD_OVERRIDE_LOCAL_APPDATA")

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


def user_cache_under(home: Path) -> "tuple[dict[str, str], Path]":
    """The environment that moves the user's cache directory under ``home``,
    and where it then is: ``~/.cache`` on Linux, ``~/Library/Caches`` on
    macOS, the Local AppData folder on Windows. Windows reads that folder
    from the shell, not from the environment, so platformdirs' documented
    override stands in for it there."""
    if sys.platform == "win32":
        local = home / "AppData" / "Local"
        return {"WIN_PD_OVERRIDE_LOCAL_APPDATA": str(local)}, local
    if sys.platform == "darwin":
        return {"HOME": str(home)}, home / "Library" / "Caches"
    return {"HOME": str(home)}, home / ".cache"


def run_child(env: "dict[str, str]", prelude: str = "") -> "dict[str, object]":
    receipt = PACKAGE_ROOT.parent / "fixtures" / "public-receipts" / "receipt-sandbox-g5.b64"
    code = CHILD.format(prelude=textwrap.dedent(prelude), receipt=str(receipt))
    dropped = (_cache.ENV_VAR, *LOCATION_VARIABLES)
    environment = {k: v for k, v in os.environ.items() if k not in dropped}
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

    def default(self, env: "dict[str, str]") -> "str | None":
        """``usable_directory`` with no ``APRV_WASM_CACHE_DIR``, under ``env``."""
        with mock.patch.dict(os.environ, env):
            for name in (_cache.ENV_VAR, *LOCATION_VARIABLES):
                if name not in env:
                    os.environ.pop(name, None)
            return _cache.usable_directory()

    def test_the_default_is_the_users_own_cache_directory(self) -> None:
        # The platform's per-user cache directory, one folder for the package
        # and one for Wasmtime in it, created private like any other.
        env, cache = user_cache_under(self.directory())
        expected = cache / APP / "wasmtime"
        self.assertEqual(os.path.normpath(expected), self.default(env))
        if POSIX:
            for made in (cache / APP, expected):
                self.assertEqual(0, stat.S_IMODE(made.stat().st_mode) & 0o077, made)

    @unittest.skipIf(sys.platform == "win32", "XDG_CACHE_HOME is a Linux and macOS variable")
    def test_an_absolute_xdg_cache_home_holds_the_default(self) -> None:
        # The XDG base directory spec's variable, which macOS honours too
        # (platformdirs 4.6.0), so one setting moves every XDG-aware cache.
        home = self.directory()
        env, _ = user_cache_under(home)
        env["XDG_CACHE_HOME"] = str(home / "xdg")
        self.assertEqual(str(home / "xdg" / APP / "wasmtime"), self.default(env))

    @unittest.skipIf(sys.platform == "win32", "XDG_CACHE_HOME is a Linux and macOS variable")
    def test_a_relative_xdg_cache_home_is_ignored(self) -> None:
        # The spec calls a relative value invalid. Taking it would put native
        # code under whatever the working directory is, so the platform
        # default stands (platformdirs 4.11.8, the reason for the floor).
        env, cache = user_cache_under(self.directory())
        env["XDG_CACHE_HOME"] = "relative/cache"
        self.assertEqual(str(cache / APP / "wasmtime"), self.default(env))

    @unittest.skipUnless(POSIX, "Windows takes the folder from the shell, not from HOME")
    def test_no_home_directory_turns_the_cache_off(self) -> None:
        # A HOME that does not expand leaves no home directory, and
        # platformdirs raises (4.12.0); the cache is then off, not an error.
        self.assertIsNone(self.default({"HOME": "~nouser"}))

    @unittest.skipUnless(POSIX, "Windows takes the folder from the shell, not from HOME")
    def test_a_relative_home_turns_the_cache_off(self) -> None:
        # platformdirs builds the path on a relative HOME as given, and a
        # relative cache directory would sit under whatever the working
        # directory is. Nothing may be created there.
        cwd = self.directory()
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(cwd)
        self.assertIsNone(self.default({"HOME": "relative"}))
        self.assertEqual([], list(cwd.iterdir()))

    def test_any_failure_naming_the_directory_turns_the_cache_off(self) -> None:
        # Not only the RuntimeError above: on Windows a folder the shell
        # cannot give is a ValueError. Whatever is raised, the cache is off.
        for error in (RuntimeError("no home"), ValueError("no folder"), KeyError("HOME")):
            with (
                self.subTest(error=type(error).__name__),
                mock.patch("platformdirs.user_cache_dir", side_effect=error),
            ):
                self.assertIsNone(self.default({}))

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
        env, _ = user_cache_under(home)
        env[_cache.ENV_VAR] = ""
        self.assertTrue(run_child(env)["verified"])
        self.assertEqual(
            [], list(home.iterdir()), "the cache was created despite the empty variable"
        )

    def test_with_no_variable_the_cache_lives_in_the_users_cache_directory(self) -> None:
        home = self.directory()
        env, cache = user_cache_under(home)
        self.assertTrue(run_child(env)["verified"])
        found = [p for p in home.rglob("modules") if p.is_dir()]
        self.assertEqual(1, len(found), [str(p) for p in home.rglob("*")][:20])
        self.assertEqual(cache / APP / "wasmtime" / "modules", found[0])


if __name__ == "__main__":
    unittest.main()
