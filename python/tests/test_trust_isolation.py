"""Trust comes from the anchors the caller passes, and from nowhere else.

This is the property the whole library exists to hold, and Python is the
language where it is easiest to lose by accident: one ``import ssl`` and a
``create_default_context()``, or a dependency that quietly pulls in
``certifi``, and pinned trust becomes "trust anything a public CA signed".

So it is asserted three ways, the same three the Go, Rust, PHP and Ruby
ports use:

* **environmentally** — a CA that this *process* genuinely trusts (planted
  into the OpenSSL default verify paths that ``ssl.create_default_context()``
  reads) buys an attacker nothing, and neither does a real public root taken
  out of this machine's own CA bundle;
* **structurally** — no module of the package imports or names anything that
  could reach a trust store or the network, and its runtime dependency set is
  exactly the one reviewed package (the Wasm runtime);
* **positively** — the anchor list that reaches the module's ``init`` is,
  byte for byte, the list the caller handed in: nothing is appended, dropped
  or substituted on the way.

Which anchors decide a chain is the module's business; what this package can
and must guarantee is that nothing else reaches it.

The scan covers ``apple_purchase_receipt_verifier/`` only. This test module
itself imports ``ssl`` and ``os`` on purpose — that is how it plants the
trust store it then proves irrelevant.
"""

import ast
import base64
import io
import json
import os
import ssl
import tempfile
import tokenize
import unittest
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from unittest import mock

from apple_purchase_receipt_verifier import Config, Reason, Verifier, _host

import _support  # also puts the module APRV_WASM names in place, for tooling


def verifier(roots: "Sequence[bytes] | None") -> Verifier:
    """Anchored on ``roots``; ``None`` is the defaults, the Apple roots
    compiled into the module."""
    return Verifier(Config(roots=roots))


def assert_refused(test: unittest.TestCase, result: Any, reason: Reason) -> None:
    """The input did not verify, and it failed for ``reason``."""
    test.assertFalse(result.verified)
    test.assertEqual(reason, failure_reason(result))


def receipt_base64(der: bytes) -> str:
    return base64.b64encode(der).decode("ascii")


def failure_reason(result: Any) -> Reason:
    assert result.failure is not None
    return result.failure.reason  # type: ignore[no-any-return]


PORT = Path(__file__).resolve().parents[1]
PACKAGE = PORT / "apple_purchase_receipt_verifier"
FIXTURES = PORT.parent / "fixtures"

#: The host CA bundles a Unix-ish machine keeps its public roots in. Same
#: list as the Rust and PHP ports scan.
HOST_CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
)


def fixture(*segments: str) -> bytes:
    return FIXTURES.joinpath(*segments).read_bytes()


def fixture_text(*segments: str) -> str:
    return fixture(*segments).decode("ascii").strip()


def cert(*segments: str) -> bytes:
    return fixture(*segments)


def pem_of(der: bytes) -> bytes:
    body = base64.encodebytes(der).decode("ascii")
    return f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n".encode("ascii")


def pem_certificates(bundle: str) -> "list[bytes]":
    """The DER of every certificate in a PEM bundle, skipping anything that is
    not base64. Whether a certificate parses is not this test's business: the
    host's store is whatever the distribution shipped."""
    out: list[bytes] = []
    marker = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    rest = bundle
    while marker in rest:
        rest = rest[rest.index(marker) + len(marker) :]
        if end not in rest:
            break
        block, rest = rest[: rest.index(end)], rest[rest.index(end) + len(end) :]
        try:
            out.append(base64.b64decode("".join(block.split()), validate=True))
        except ValueError:
            continue
    return out


def host_trust_store_roots() -> "list[bytes]":
    """This machine's public roots, or an empty list where there is no bundle."""
    for path in HOST_CA_BUNDLES:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        roots = pem_certificates(text)
        if roots:
            return roots
    return []


class ProcessTrustStoreTest(unittest.TestCase):
    """The strongest offline form of the pinning claim: make a CA genuinely
    trusted by this process, prove Python's own default TLS trust store
    accepts it, and show the library still refuses the chain under it."""

    def plant(self, root: bytes) -> None:
        """Installs ``root`` as the *only* certificate authority this process
        trusts, for the duration of the test, and asserts that it took.

        ``SSL_CERT_FILE`` / ``SSL_CERT_DIR`` are OpenSSL's own default verify
        paths — the ones ``ssl.create_default_context()`` reads.
        ``REQUESTS_CA_BUNDLE`` / ``CURL_CA_BUNDLE`` are the HTTP-client
        conventions layered on top. A library that consulted any of them,
        directly or through a dependency, would start trusting whatever a
        host operator configured.
        """
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        bundle = Path(directory.name) / "planted-ca-bundle.pem"
        bundle.write_bytes(pem_of(root))

        patcher = mock.patch.dict(
            os.environ,
            {
                "SSL_CERT_FILE": str(bundle),
                "SSL_CERT_DIR": str(bundle.parent),
                "REQUESTS_CA_BUNDLE": str(bundle),
                "CURL_CA_BUNDLE": str(bundle),
            },
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        # The premise. Without it the refusals below would prove nothing:
        # they could be failing for any reason at all.
        #
        # Asserted only where the planting mechanism applies. A Python built
        # against a platform trust store (Windows, and macOS builds using
        # `truststore`) ignores SSL_CERT_FILE, and this process cannot write
        # to the certificate store or the keychain without administrative
        # rights. `openssl_cafile_env` naming SSL_CERT_FILE is that
        # interpreter telling us the variable is the mechanism.
        if ssl.get_default_verify_paths().openssl_cafile_env != "SSL_CERT_FILE":
            self.skipTest("this interpreter does not take its default CAs from SSL_CERT_FILE")
        trusted = ssl.create_default_context().get_ca_certs(binary_form=True)
        self.assertIn(
            root,
            trusted,
            "the premise failed: the planted root is not in this process's default trust store, "
            "so this test proves nothing",
        )

    def test_a_receipt_ca_the_process_trusts_is_still_not_an_anchor(self) -> None:
        root = cert("generated-0.7", "receipt-root.der")
        text = receipt_base64(fixture("generated-0.7", "receipt.der"))
        self.plant(root)

        # Positive control first: the only thing separating this from the
        # refusals below is which anchors were passed.
        result = verifier([root]).verify_receipt(text)
        self.assertTrue(result.verified, result.failure)

        with self.subTest(anchors="the module's Apple roots"):
            result = verifier(None).verify_receipt(text)
            assert_refused(self, result, Reason.UNTRUSTED_CHAIN)

    def test_a_jws_ca_the_process_trusts_is_still_not_an_anchor(self) -> None:
        root = cert("generated", "jws-root.der")
        jws = fixture_text("generated", "transaction.jws")
        self.plant(root)

        result = verifier(None).verify_signed_data(jws)
        assert_refused(self, result, Reason.UNTRUSTED_CHAIN)

    def test_the_jws_root_the_process_trusts_verifies_when_the_caller_passes_it(self) -> None:
        root = cert("generated", "jws-root.der")
        self.plant(root)
        result = verifier([root]).verify_signed_data(fixture_text("generated", "transaction.jws"))
        self.assertTrue(result.verified, result.failure)

    def test_an_empty_anchor_list_is_a_configuration_error_not_a_fallback(self) -> None:
        # The failure mode this rules out: "no anchors given, so use the
        # system ones". There is no ambient set to fall back to, and asking
        # for one is refused at construction rather than silently widened.
        self.plant(cert("generated-0.7", "receipt-root.der"))
        with self.assertRaises(ValueError):
            Verifier(Config(roots=[]))


class HostTrustStoreTest(unittest.TestCase):
    """The other direction: this machine's real public roots have no standing
    unless the caller passes them, and passing them buys nothing either."""

    def setUp(self) -> None:
        self.host_roots = host_trust_store_roots()
        if not self.host_roots:
            self.skipTest("no host CA bundle on this machine to read genuine public roots from")

    def test_a_real_public_root_is_not_an_anchor_unless_the_caller_passes_it(self) -> None:
        public_root = self.host_roots[0]
        text = receipt_base64(fixture("generated-0.7", "receipt.der"))

        # Anchored on a genuine public CA — one millions of TLS clients
        # accept — the fixture chain is still refused: the anchor did not
        # certify it.
        result = verifier([public_root]).verify_receipt(text)
        assert_refused(self, result, Reason.UNTRUSTED_CHAIN)

        # And it gains nothing from sitting next to Apple's roots in the
        # caller's list.
        result = verifier([public_root, *_support.apple_roots()]).verify_receipt(text)
        assert_refused(self, result, Reason.UNTRUSTED_CHAIN)

    def test_the_host_roots_do_not_verify_genuine_apple_material(self) -> None:
        # The complement of the pinning test: hand the library this machine's
        # entire trust store as its anchors and genuine Apple-signed material
        # is refused, because none of those roots issued it.
        genuine = fixture_text("public-receipts", "receipt-sandbox-g5.b64")

        result = verifier(None).verify_receipt(genuine)
        self.assertTrue(result.verified, result.failure)

        result = verifier(self.host_roots).verify_receipt(genuine)
        assert_refused(self, result, Reason.UNTRUSTED_CHAIN)


class AnchorsReachTheModuleUnchangedTest(unittest.TestCase):
    """The positive half: exactly the caller's anchors, in order, byte for
    byte, reach the module's ``init``.

    A source scan proves nothing was *imported*; this proves nothing was
    *added*: an anchor list is not augmented, reordered, or substituted
    between the constructor and the module."""

    def sent_to_init(self, roots: "Sequence[bytes] | None") -> "list[bytes]":
        seen: list[bytes] = []
        real = _host.Pool

        def spy(runtime: Any, config_json: bytes, *rest: Any) -> Any:
            seen.append(config_json)
            return real(runtime, config_json, *rest)

        with mock.patch.object(_host, "Pool", spy):
            verifier(roots)
        self.assertEqual(1, len(seen))
        document = json.loads(seen[0])
        self.assertEqual(["roots"], list(document))
        return [base64.b64decode(r, validate=True) for r in document["roots"]]

    def test_the_callers_list_reaches_init_in_order(self) -> None:
        passed = [cert("generated", "jws-root.der"), cert("generated-0.7", "receipt-root.der")]
        self.assertEqual(passed, self.sent_to_init(passed))
        self.assertEqual(passed[::-1], self.sent_to_init(passed[::-1]))

    def test_the_defaults_send_an_empty_list_and_nothing_else(self) -> None:
        # Empty means the three Apple roots compiled into the module. The
        # package carries no copy of them, so nothing from this machine, or
        # anywhere else, can be folded into the default set on the way.
        self.assertIsNone(Config().roots)
        self.assertEqual([], self.sent_to_init(Config().roots))

    def test_a_duplicate_is_dropped_by_config_and_nothing_is_added(self) -> None:
        one = cert("generated", "jws-root.der")
        self.assertEqual([one], self.sent_to_init([one, one]))


class SourceScanTest(unittest.TestCase):
    """Cross-port rule S1, mechanised: no module of this package can reach an
    operating-system trust store, a CA bundle, or the network."""

    #: Modules that would hand a trust decision to the platform, to a
    #: downloaded CA bundle, or to a peer on the network. ``truststore`` is
    #: the one that matters most here: it is a real, popular package whose
    #: entire purpose is to replace ``ssl``'s anchors with the OS store.
    FORBIDDEN_IMPORTS = frozenset(
        {
            "ssl",
            "certifi",
            "truststore",
            "urllib",
            "urllib3",
            "requests",
            "httpx",
            "aiohttp",
            "http",
            "socket",
            "socketserver",
            "ftplib",
            "smtplib",
            "xmlrpc",
            # A shell-out is the same leak wearing a hat: `security
            # find-certificate`, `openssl verify`, `curl`.
            "subprocess",
            "ctypes",
            # Dates and their US Pacific renderings are the module's (R38).
            # The crypto, X.509 and ASN.1 libraries are banned for every
            # wrapper in one place, tools/check-one-implementation.mjs.
            "zoneinfo",
        }
    )

    #: Every module the package is allowed to import. An allowlist as well as
    #: a denylist, because the denylist can only ban what we thought of —
    #: this catches the next `truststore` before it has a name.
    ALLOWED_IMPORTS = frozenset(
        {
            "base64",
            "collections",
            "contextlib",
            "dataclasses",
            "enum",
            "hashlib",
            "importlib",
            "json",
            "os",
            "pathlib",
            "secrets",
            "stat",
            "struct",
            "sys",
            "tempfile",
            "threading",
            "time",
            "types",
            "typing",
            "wasmtime",
        }
    )

    #: Names that can only mean one thing in code. Matched as identifiers,
    #: not substrings, so a word appearing inside another name is not a hit.
    FORBIDDEN_NAMES = frozenset(
        {
            "SSLContext",
            "create_default_context",
            "load_default_certs",
            "load_verify_locations",
            "set_default_verify_paths",
            "get_default_verify_paths",
            "certifi",
            "truststore",
            "urlopen",
            "urlretrieve",
            "socket",
            "ssl",
        }
    )

    #: Literals that would name a trust store or a network endpoint. Scanned
    #: over string constants only, docstrings excluded — prose legitimately
    #: names the Apple CA page it does not fetch.
    FORBIDDEN_LITERALS = (
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "ca-certificates",
        "cacert.pem",
        "/etc/ssl",
        "/etc/pki",
        "keychain",
        "Keychain",
        "http://",
        "https://",
    )

    def sources(self) -> "list[tuple[Path, str]]":
        files = sorted(PACKAGE.rglob("*.py"))
        self.assertGreaterEqual(
            len(files), 6, f"the source scan found only {len(files)} files under {PACKAGE}"
        )
        return [(path, path.read_text(encoding="utf-8")) for path in files]

    def test_no_module_imports_a_trust_store_or_a_network_client(self) -> None:
        for path, source in self.sources():
            for module in imported_modules(ast.parse(source)):
                top = module.split(".")[0]
                self.assertNotIn(
                    top,
                    self.FORBIDDEN_IMPORTS,
                    f"{path.name} imports {module}; anchors come only from the caller",
                )

    def test_the_import_set_is_exactly_the_reviewed_one(self) -> None:
        imported = {
            module.split(".")[0]
            for _, source in self.sources()
            for module in imported_modules(ast.parse(source))
        }
        self.assertEqual(
            self.ALLOWED_IMPORTS,
            imported,
            "the package's import set changed; review the new module for trust-store "
            "or network access before widening the allowlist",
        )

    def test_no_module_names_a_trust_store_api(self) -> None:
        # Comments and docstrings legitimately name these to explain why they
        # are not used, so the ban is on code.
        for path, source in self.sources():
            names = identifiers(source)
            for forbidden in sorted(self.FORBIDDEN_NAMES & names):
                self.fail(f"{path.name} names {forbidden} in code")

    def test_no_string_literal_names_a_ca_bundle_or_a_url(self) -> None:
        for path, source in self.sources():
            for literal in non_docstring_strings(ast.parse(source)):
                for forbidden in self.FORBIDDEN_LITERALS:
                    self.assertNotIn(
                        forbidden, literal, f"{path.name} has a string literal naming {forbidden}"
                    )

    def test_the_runtime_dependency_set_is_exactly_the_reviewed_one(self) -> None:
        # A new runtime dependency is a supply-chain decision, and it should
        # not be possible to make one by accident: any HTTP client on this
        # list would drag `certifi` in with it.
        declared = declared_dependencies((PORT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(["wasmtime"], sorted(declared))

    def test_no_module_is_named_for_verification_logic(self) -> None:
        # Mirrors rust/tools' layering rule: the wrappers hold none of it.
        for path in sorted(PACKAGE.rglob("*.py")):
            for word in ("asn1", "x509", "cms", "chain", "crypto", "der"):
                self.assertNotIn(word, path.stem.split("_"), f"{path.name} names {word}")


def imported_modules(tree: ast.Module) -> "list[str]":
    """Every absolute module name imported by a parsed source file."""
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            modules.append(node.module)
    return modules


def identifiers(source: str) -> "set[str]":
    """Every identifier in a source file, with comments and strings removed."""
    names: set[str] = set()
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.NAME:
            names.add(token.string)
    return names


def non_docstring_strings(tree: ast.Module) -> "list[str]":
    """Every string literal that is not a module, class or function docstring."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                docstrings.add(id(first.value))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def declared_dependencies(pyproject: str) -> "list[str]":
    """The distribution names in ``[project] dependencies``.

    Hand-parsed rather than read with ``tomllib``: this suite runs on the
    3.10 floor the package claims, where ``tomllib`` does not exist and no
    TOML parser is a dependency.
    """
    section = pyproject.split("\n[project]\n", 1)
    if len(section) != 2:
        raise AssertionError("pyproject.toml has no [project] section")
    body = section[1].split("\n[", 1)[0]
    marker = "\ndependencies = ["
    if marker not in body:
        raise AssertionError("pyproject.toml declares no [project] dependencies")
    listing = body.split(marker, 1)[1].split("]", 1)[0]
    names: list[str] = []
    for line in listing.splitlines():
        entry = line.strip().strip(",").strip('"')
        if not entry:
            continue
        names.append(distribution_name(entry))
    return names


def distribution_name(requirement: str) -> str:
    """The distribution name out of a PEP 508 requirement string."""
    name = requirement
    for separator in ("[", "<", ">", "=", "!", "~", ";", " "):
        name = name.split(separator, 1)[0]
    return name.strip()


if __name__ == "__main__":
    unittest.main()
