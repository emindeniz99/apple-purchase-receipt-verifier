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
  exactly the two reviewed packages;
* **positively** — the anchor list that reaches the chain builder is, object
  for object, the list the caller handed in: nothing is appended, dropped or
  substituted on the way.

The scan covers ``apple_purchase_receipt_verifier/`` only. This test module
itself imports ``ssl`` and ``os`` on purpose — that is how it plants the
trust store it then proves irrelevant.
"""

import ast
import io
import os
import ssl
import tempfile
import tokenize
import unittest
import warnings
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from unittest import mock

from apple_purchase_receipt_verifier import (
    JwsVerifier,
    ReceiptVerifier,
    VerificationError,
    apple_jws_roots,
    apple_receipt_roots,
    verify_receipt_core,
)

# Imported from the module that defines them, and patched where the two
# verifier modules bound them: that binding is the seam an ambient anchor
# set would have to pass through.
from apple_purchase_receipt_verifier._chain import build_and_validate_path, validate_pair
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

PORT = Path(__file__).resolve().parents[1]
PACKAGE = PORT / "apple_purchase_receipt_verifier"
FIXTURES = PORT.parent / "fixtures"
BUNDLE = "com.example.app"

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


def cert(*segments: str) -> x509.Certificate:
    return x509.load_der_x509_certificate(fixture(*segments))


def pem_certificates(bundle: str) -> "list[x509.Certificate]":
    """Every certificate in a PEM bundle, skipping anything unparseable.

    Warnings are silenced for the parse only: a host trust store is whatever
    the distribution shipped, and at least one root in a stock Debian bundle
    carries a non-positive serial that ``cryptography`` deprecates. That is
    the host's business, not this library's, and the noise would otherwise
    land in every CI log.
    """
    out: list[x509.Certificate] = []
    marker = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    rest = bundle
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        while marker in rest:
            rest = rest[rest.index(marker) :]
            if end not in rest:
                break
            block, rest = rest[: rest.index(end) + len(end)], rest[rest.index(end) + len(end) :]
            try:
                out.append(x509.load_pem_x509_certificate(block.encode()))
            except ValueError:
                continue
    return out


def host_trust_store_roots() -> "list[x509.Certificate]":
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

    def plant(self, root: x509.Certificate) -> None:
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
        bundle.write_bytes(root.public_bytes(Encoding.PEM))

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
            root.public_bytes(Encoding.DER),
            trusted,
            "the premise failed: the planted root is not in this process's default trust store, "
            "so this test proves nothing",
        )

    def test_a_receipt_ca_the_process_trusts_is_still_not_an_anchor(self) -> None:
        root = cert("generated", "receipt-root.der")
        der = fixture("generated", "receipt.der")
        self.plant(root)

        # Positive control first: the only thing separating this from the
        # refusals below is which anchors were passed.
        self.assertEqual(BUNDLE, ReceiptVerifier([root], BUNDLE).verify(der).bundle_id)

        for anchors, what in (
            (apple_receipt_roots(), "the bundled Apple roots"),
            (apple_jws_roots(), "the bundled JWS roots"),
        ):
            with self.subTest(anchors=what):
                with self.assertRaises(VerificationError) as ctx:
                    ReceiptVerifier(anchors, BUNDLE).verify(der)
                self.assertEqual("INVALID_CHAIN", ctx.exception.reason)

                # And the primitive under it, which is where the path
                # builder lives.
                with self.assertRaises(VerificationError) as ctx:
                    verify_receipt_core(der, anchors)
                self.assertEqual("INVALID_CHAIN", ctx.exception.reason)

    def test_a_jws_ca_the_process_trusts_is_still_not_an_anchor(self) -> None:
        root = cert("generated", "jws-root.der")
        jws = fixture_text("generated", "transaction.jws")
        self.plant(root)

        verifier = JwsVerifier([root], BUNDLE, ["Sandbox"])
        self.assertEqual(BUNDLE, verifier.verify_transaction(jws)["bundleId"])

        with self.assertRaises(VerificationError) as ctx:
            JwsVerifier(apple_jws_roots(), BUNDLE, ["Sandbox"]).verify_transaction(jws)
        self.assertEqual("INVALID_CHAIN", ctx.exception.reason)

    def test_an_empty_anchor_list_is_a_configuration_error_not_a_fallback(self) -> None:
        # The failure mode this rules out: "no anchors given, so use the
        # system ones". There is no ambient set to fall back to, and asking
        # for one is refused at construction rather than silently widened.
        self.plant(cert("generated", "receipt-root.der"))
        with self.assertRaises(ValueError):
            ReceiptVerifier([], BUNDLE)
        with self.assertRaises(ValueError):
            JwsVerifier([], BUNDLE, ["Sandbox"])
        with self.assertRaises(ValueError):
            verify_receipt_core(fixture("generated", "receipt.der"), [])


class HostTrustStoreTest(unittest.TestCase):
    """The other direction: this machine's real public roots have no standing
    unless the caller passes them, and passing them buys nothing either."""

    def setUp(self) -> None:
        self.host_roots = host_trust_store_roots()
        if not self.host_roots:
            self.skipTest("no host CA bundle on this machine to read genuine public roots from")

    def test_a_real_public_root_is_not_an_anchor_unless_the_caller_passes_it(self) -> None:
        public_root = self.host_roots[0]
        der = fixture("generated", "receipt.der")

        # Anchored on a genuine public CA — one millions of TLS clients
        # accept — the fixture chain is still refused: the anchor did not
        # certify it.
        with self.assertRaises(VerificationError) as ctx:
            verify_receipt_core(der, [public_root])
        self.assertEqual("INVALID_CHAIN", ctx.exception.reason)

        # And it gains nothing from sitting next to Apple's roots in the
        # caller's list.
        with self.assertRaises(VerificationError) as ctx:
            verify_receipt_core(der, [public_root, *apple_receipt_roots()])
        self.assertEqual("INVALID_CHAIN", ctx.exception.reason)

    def test_the_host_roots_do_not_verify_genuine_apple_material(self) -> None:
        # The complement of the pinning test: hand the library this machine's
        # entire trust store as its anchors and genuine Apple-signed material
        # is refused, because none of those roots issued it.
        genuine = fixture_text("public-receipts", "receipt-sandbox-g5.b64")
        apple_bundle_id = "dev.bonzer.weeka.app"

        self.assertEqual(
            apple_bundle_id,
            ReceiptVerifier(apple_receipt_roots(), apple_bundle_id).verify(genuine).bundle_id,
        )
        with self.assertRaises(VerificationError) as ctx:
            ReceiptVerifier(self.host_roots, apple_bundle_id).verify(genuine)
        self.assertEqual("INVALID_CHAIN", ctx.exception.reason)

    def test_no_bundled_anchor_came_from_this_machines_trust_store(self) -> None:
        # If the package ever started folding the host's roots into its own
        # set, this is the first thing that would change.
        host = {root.public_bytes(Encoding.DER) for root in self.host_roots}
        for anchor in [*apple_receipt_roots(), *apple_jws_roots()]:
            self.assertNotIn(
                anchor.public_bytes(Encoding.DER),
                host,
                f"{anchor.subject.rfc4514_string()} came from the host trust store",
            )


class AnchorsReachTheChainBuilderUnchangedTest(unittest.TestCase):
    """The positive half: exactly the caller's anchors, in order, by identity.

    A source scan proves nothing was *imported*; this proves nothing was
    *added* — an anchor list is not augmented, reordered, deduplicated or
    substituted between the constructor and the chain builder.
    """

    def test_the_receipt_path_builder_sees_the_callers_list(self) -> None:
        passed = [cert("generated", "jws-root.der"), cert("generated", "receipt-root.der")]
        seen: list[Sequence[x509.Certificate]] = []
        real = build_and_validate_path

        def spy(
            target: x509.Certificate,
            candidates: "Sequence[x509.Certificate]",
            anchors: "Sequence[x509.Certificate]",
            at: datetime,
        ) -> None:
            seen.append(anchors)
            real(target, candidates, anchors, at)

        with mock.patch("apple_purchase_receipt_verifier.receipt.build_and_validate_path", spy):
            ReceiptVerifier(passed, BUNDLE).verify(fixture("generated", "receipt.der"))

        self.assertEqual(1, len(seen))
        self.assert_anchors_are(passed, seen[0])

    def test_the_jws_path_builder_sees_the_callers_list(self) -> None:
        passed = [cert("generated", "receipt-root.der"), cert("generated", "jws-root.der")]
        seen: list[Sequence[x509.Certificate]] = []
        real = validate_pair

        def spy(
            leaf: x509.Certificate,
            intermediate: x509.Certificate,
            anchors: "Sequence[x509.Certificate]",
            at: datetime,
        ) -> None:
            seen.append(anchors)
            real(leaf, intermediate, anchors, at)

        with mock.patch("apple_purchase_receipt_verifier.jws.validate_pair", spy):
            JwsVerifier(passed, BUNDLE, ["Sandbox"]).verify_transaction(
                fixture_text("generated", "transaction.jws")
            )

        self.assertEqual(1, len(seen))
        self.assert_anchors_are(passed, seen[0])

    def assert_anchors_are(
        self,
        expected: "Sequence[x509.Certificate]",
        actual: "Sequence[x509.Certificate]",
    ) -> None:
        self.assertEqual(len(expected), len(actual), "the anchor set changed size in transit")
        for index, (want, got) in enumerate(zip(expected, actual)):
            self.assertIs(want, got, f"anchor {index} is not the object the caller passed")


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
        }
    )

    #: Every module the package is allowed to import. An allowlist as well as
    #: a denylist, because the denylist can only ban what we thought of —
    #: this catches the next `truststore` before it has a name.
    ALLOWED_IMPORTS = frozenset(
        {
            "asn1crypto",
            "base64",
            "binascii",
            "collections",
            "cryptography",
            "datetime",
            "hashlib",
            "hmac",
            "json",
            "pathlib",
            "re",
            "time",
            "typing",
            "zoneinfo",
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
        self.assertEqual(["asn1crypto", "cryptography"], sorted(declared))


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
    3.9 floor the package claims, where ``tomllib`` does not exist and no
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
