#!/usr/bin/env node
// The one-implementation gate (ARCHITECTURE.md §9): no wrapper around
// aprv.wasm may parse, verify or decide anything itself, so no non-Java
// wrapper may call a crypto, X.509, ASN.1, CMS or JWS API outside its tests.
//
// This is the one list of those APIs. The packages' own tests keep only
// what a line scan cannot see (a manifest's dependencies, an import
// allowlist, the compiled assembly's references, the class files'
// bytecode level) and the rules outside this gate's subject (network,
// environment, randomness). Run it before pushing a wrapper change.
//
//   node tools/check-one-implementation.mjs [--enforce <all|lang,lang,...>] [--root <dir>]
//
// Lists every hit, per language. --root scans another tree laid out like
// this repository (tools/test/check-one-implementation.test.mjs plants
// every known bypass in one). Without --enforce it only reports; with
// --enforce it exits 1 on a hit in any listed language. MIGRATION.md
// Phase 7 deleted the hand-written verifiers and the wrappers' copies of
// the roots, so CI runs `--enforce all`.
//
// What stays allowed, because a wrapper needs it without deciding trust:
// a CSPRNG for the module's random-get import, and a SHA-256 to check a
// copy of aprv.wasm or a downloaded aprv binary against its pin.
//
// Out of scope by design: the Java main artifact (java/, the independent
// implementation, DECISIONS.md R33, except java/src/shared, which the
// -wasm jar compiles too), the Rust core, every test, fuzz,
// bench and sample directory, and generated bindings.
//
// A language's `allow` list names, per file, the API tokens that file may
// use and why (OD-04 in docs/rust-core/STATUS.md): a public type the 0.7
// API carries DER in and out with, or the file that hashes a module
// against its pin, never a parse or a trust decision. An
// allowed token is removed from the line before the banned patterns are
// applied, so anything else on that line, or the same token in any other
// file, is still a hit. An entry whose file no longer uses its token is
// reported as stale, so the list only shrinks.
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

// Where each wrapper's shipped source lives, the files that count, the
// comment syntax whose whole-line comments are skipped (so prose may name
// what the code avoids), and the APIs it must not reach.
const LANGS = {
  node: {
    dirs: ['node/src'],
    files: /\.(m?[jt]s|cjs|cts|mts)$/,
    comments: 'js',
    banned: [
      [/\bfrom\s+['"](node:)?crypto['"]|require\(\s*['"](node:)?crypto['"]\s*\)|import\(\s*['"](node:)?crypto['"]\s*\)|\bnode:crypto\b/, 'node:crypto'],
      [/\bcrypto\.subtle\b|\bSubtleCrypto\b|\bsubtle\./, 'WebCrypto subtle'],
      [/['"](asn1js|pkijs|jose|node-forge|@peculiar\/[^'"]+|jsrsasign)['"]/, 'a JS crypto/ASN.1 library'],
      [/\bX509Certificate\b|\bcreate(Verify|PublicKey|Hash|Hmac)\b|\bverify(Es256|Signature)\b/, 'a certificate, key, hash or signature API'],
      [/asn1|\bDER\b reader|\bparseCertificate\b|\bcms\b/i, 'an ASN.1, DER or CMS reader'],
    ],
  },
  python: {
    dirs: ['python/apple_purchase_receipt_verifier', 'python/src'],
    files: /\.py$/,
    comments: 'python',
    // At a line's start or after a `;` or `:`, and anywhere in a comma list.
    banned: [
      [/(^|[;:])\s*(from|import)\s+([\w.]+(\s+as\s+\w+)?\s*,\s*)*(cryptography|OpenSSL|asn1crypto|pyasn1|ecdsa|Crypto|Cryptodome|jwt|jose)\b/, 'a Python crypto/ASN.1 library'],
      [/(^|[;:])\s*(from|import)\s+([\w.]+(\s+as\s+\w+)?\s*,\s*)*(ssl|hmac)\b/, 'ssl or hmac'],
    ],
  },
  go: {
    dirs: ['go'],
    files: /(?<!_test)\.go$/,
    skipDirs: ['go/tools', 'go/fuzz', 'go/bench', 'go/examples', 'go/cmd'],
    comments: 'go',
    banned: [
      [/"(crypto\/(x509(\/pkix)?|ecdsa|rsa|elliptic|ecdh|ed25519|tls|dsa|sha1|sha256|sha512|hmac|subtle)|encoding\/(asn1|pem)|math\/big|golang\.org\/x\/crypto\/[^"]*|github\.com\/[^"]*\/(jwt|jose|pkcs7)[^"]*)"/, 'a Go crypto/X.509/ASN.1 package'],
      [/\bx509\.(SystemCertPool|NewCertPool|CertPool|VerifyOptions|ParseCertificates?|ParseCertificateRequest)\b|\bCheckSignatureFrom\b|\bSetDefaultPaths\b/, 'a certificate parse or platform trust evaluation'],
    ],
    allow: [
      { file: 'go/config.go', token: /"crypto\/x509"/, why: "Config's roots are *x509.Certificate (the 0.7 API); only .Raw, the DER, crosses into the module" },
      { file: 'go/internal/wasm/wasm.go', token: /"crypto\/sha256"/, why: 'checks the embedded aprv.wasm against its pinned SHA-256' },
    ],
  },
  swift: {
    dirs: ['swift/Sources'],
    files: /\.swift$/,
    banned: [
      // Any attribute or access level before `import`, and a scoped import
      // (`import struct CryptoKit.SHA256`).
      [/\bimport\s+(?:(?:struct|class|enum|protocol|func|var|let|typealias)\s+)?(Crypto\w*|_CryptoExtras|X509|SwiftASN1|Security\w*|CommonCrypto)\b/, 'a Swift crypto/X.509/ASN.1 module'],
      // A name qualified by one of those modules (`Crypto.P256`): a scoped
      // import loads the whole module, so any of its types is reachable
      // that way from the file that imports it.
      [/\b(?:Crypto\w*|_CryptoExtras|X509|SwiftASN1|Security\w*|CommonCrypto)\s*\.\s*[A-Z_a-z]/, 'a name qualified by a Swift crypto/X.509/ASN.1 module'],
      [/\bSec(Trust|Certificate)/, 'the Security framework\'s trust or certificate API'],
    ],
    // Only the SHA-256 type, by a scoped import that is the whole line: a
    // plain `import Crypto`, an attribute or a wider access level on it,
    // anything after it on the line, or any other name from the module is
    // still a hit in this file too.
    allow: [
      { file: 'swift/Sources/ApplePurchaseReceiptVerifier/Host/AprvModule.swift', token: /^\s*(?:internal\s+)?import\s+struct\s+Crypto\.SHA256\s*$/, why: 'checks the bundled aprv.wasm against its pinned SHA-256 (swift-crypto; CryptoKit on Apple platforms)' },
    ],
    comments: 'swift',
  },
  ruby: {
    dirs: ['ruby/lib'],
    files: /\.rb$/,
    comments: 'ruby',
    banned: [
      [/OpenSSL|require\s*\(?\s*['"]openssl['"]/, 'OpenSSL'],
      [/require\s*\(?\s*['"](jwt|jose|json\/jwt)['"]/, 'a Ruby JWT library'],
      [/\bX509\b|\bPKCS7\b|\bASN1\b|\bECDSA\b|\bx5c\b|base64url/i, 'an X.509, PKCS #7, ASN.1, ECDSA or JWS name'],
      [/\bCMS\b|Signature/, 'a CMS or signature name'],
    ],
  },
  dotnet: {
    dirs: ['dotnet/src'],
    files: /\.cs$/,
    comments: 'csharp',
    banned: [
      [/System\.Security\.Cryptography\.(Pkcs|X509Certificates)|System\.Formats\.Asn1|Asn(Reader|Writer|Decoder)|\bX509Certificate2?\b|X509Chain|SignedCms|SignerInfo/, '.NET X.509/CMS/ASN.1'],
      [/\b(ECDsa|RSA|DSA)\s*\.\s*Create\b|ECDsa|\bRSA(Cng|OpenSsl)?\b|RSACryptoServiceProvider|Verify(Data|Hash)|Org\.BouncyCastle/, '.NET signature verification'],
    ],
    allow: [
      { file: 'dotnet/src/ApplePurchaseReceiptVerifier/Config.cs', token: /using System\.Security\.Cryptography\.X509Certificates;|\bX509Certificate2\b/g, why: 'Config.Roots and the Config constructor\'s roots take X509Certificate2 (the 0.7 type); only its RawData, the DER, reaches the module' },
      { file: 'dotnet/src/ApplePurchaseReceiptVerifier/Internal/Certificates.cs', token: /using System\.Security\.Cryptography\.X509Certificates;|\bX509Certificate2\b/g, why: "wraps DER in an X509Certificate2 for Config.Roots above; no chain, no key, no signature" },
    ],
  },
  php: {
    dirs: ['php/src'],
    files: /\.php$/,
    comments: 'php',
    banned: [
      [/\bopenssl_[a-z0-9_]+\s*\(/i, 'openssl_*'],
      [/\bsodium_crypto|phpseclib|\\?FG\\ASN1|Firebase\\JWT|\bJose\\/i, 'a PHP crypto/ASN.1/JWT library'],
      // Functions, not methods: `->name(` and `::name(` are a class's own.
      [/(?<![>:$\w])(gmp_\w+|bcpowmod|hash_hmac\w*|mcrypt_\w+)\s*\(/i, 'a big-number, HMAC or mcrypt function'],
    ],
  },
  'java-wasm': {
    comments: 'java',
    // java/src/shared holds the classes the -wasm jar compiles together
    // with the main artifact; they ship in this jar too, so they are held
    // to its rule (the rest of java/ is out of scope, above).
    dirs: ['java-wasm/src/main', 'java/src/shared'],
    files: /\.java$/,
    banned: [
      [/\borg\.bouncycastle\b|\bjava\.security\.cert\b|\bjava\.security\.Signature\b|\bjavax\.crypto\b|\bjava\.security\.KeyFactory\b|\bsun\.security\b/, 'a Java crypto/X.509 API'],
    ],
    // The -wasm artifact copies java/'s 0.7 public API (R33), whose roots
    // are java.security.cert.X509Certificate: the same case as Go's and
    // .NET's entries (OD-04). Only the imports are allowed; any other use of
    // java.security.cert, or these imports anywhere else, is still a hit.
    allow: [
      { file: 'java/src/shared/java/io/github/emindeniz99/applepurchasereceiptverifier/Config.java', token: /import java\.security\.cert\.X509Certificate;/, why: 'Config.roots() holds X509Certificate (the 0.7 API); only getEncoded(), the DER, reaches the module' },
      { file: 'java-wasm/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleRootCerts.java', token: /import java\.security\.cert\.(CertificateException|CertificateFactory|X509Certificate);/, why: 'AppleRootCerts returns the three bundled roots as X509Certificate for the 0.7 API; the module holds its own copy and decides trust' },
      { file: 'java-wasm/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/InitConfig.java', token: /import java\.security\.cert\.(CertificateEncodingException|X509Certificate);/, why: "takes each root's getEncoded() DER for init's configuration (both engines) and the SHA-256s /v1/info lists; nothing is parsed or checked" },
    ],
  },
};

// A line is skipped as a comment only when the whole of it is one: its
// first non-blank characters open a line comment (`//`, or `#` where that
// is a comment), or open a block comment (`/*`, `/**`), or continue one
// (`*`, `*/`) right after such a line; and a block comment's line counts
// only when no code follows its `*/`. Nothing is stripped from the middle
// of a line, because that cannot be done right without parsing string
// literals: `"http://x"; require(...)` would lose the call. A line that
// holds an interpolation opener is never skipped, since inside a
// multi-line string it runs code. So a skipped line is prose or string
// text, never code. A line inside a block comment that does not start
// with `*` is still scanned, as is a `*` line that follows code (a
// multiplication carried over, a generator method); a hit there is a
// false positive to reword, not a bypass.
const SYNTAX = {
  js: { slash: true, interpolation: /\$\{/ },
  go: { slash: true }, // raw strings do not interpolate
  java: { slash: true }, // text blocks do not interpolate
  csharp: { slash: true, interpolation: /\{/ }, // $"..." and $"""...""" interpolate any brace
  swift: { slash: true, interpolation: /\\#*\(/ },
  php: { slash: true, hash: /^\s*#(?!\[)/, interpolation: /\{\$|\$\{/ }, // `#[` is an attribute
  ruby: { hash: /^\s*#/, interpolation: /#\{/ },
  python: { hash: /^\s*#/, interpolation: /\{/ }, // f-strings
};

function commentLines(lines, syntax) {
  let inBlock = false;
  return lines.map((line) => {
    const block = syntax.slash && (/^\s*\/\*/.test(line) || (inBlock && /^\s*\*/.test(line)));
    inBlock = false;
    if (syntax.interpolation?.test(line)) return false;
    if (syntax.slash && /^\s*\/\//.test(line)) return true;
    if (syntax.hash?.test(line)) return true;
    if (!block) return false;
    if (!line.includes('*/')) return (inBlock = true);
    return !/\*\/\s*\S/.test(line);
  });
}

const SKIP = /(^|\/)(tests?|__tests__|spec|fuzz|bench|benches|samples?|examples?|generated|node_modules|dist|build|target|vendor|\.build)(\/|$)/;

const USAGE = 'usage: node tools/check-one-implementation.mjs [--enforce <all|lang,lang,...>] [--root <dir>]';
let args;
try {
  args = parseArgs({ options: { enforce: { type: 'string' }, root: { type: 'string', default: ROOT } } });
} catch {
  console.error(USAGE);
  process.exit(2);
}
const { root } = args.values;
const enforce = new Set(args.values.enforce === 'all' ? Object.keys(LANGS) : args.values.enforce?.split(','));
for (const l of enforce) {
  if (!LANGS[l]) {
    console.error(`check-one-implementation: unknown language ${l}; known: ${Object.keys(LANGS).join(', ')}`);
    process.exit(2);
  }
}

let failing = 0;
const used = new Set();
for (const [lang, spec] of Object.entries(LANGS)) {
  const hits = [];
  let files = 0;
  for (const dir of spec.dirs) {
    const abs = join(root, dir);
    if (!existsSync(abs)) continue;
    for (const entry of readdirSync(abs, { recursive: true, withFileTypes: true })) {
      if (entry.isDirectory()) continue;
      const path = join(entry.parentPath, entry.name);
      const rel = relative(root, path);
      if (!spec.files.test(rel) || SKIP.test(relative(abs, path)) || spec.skipDirs?.some((d) => rel.startsWith(`${d}/`))) continue;
      files++;
      const allowed = (spec.allow ?? []).filter((a) => a.file === rel);
      const lines = readFileSync(path, 'utf8').split('\n');
      const comment = spec.comments ? commentLines(lines, SYNTAX[spec.comments]) : [];
      lines.forEach((line, i) => {
        if (comment[i]) return;
        let rest = line;
        for (const a of allowed) {
          const stripped = rest.replace(new RegExp(a.token.source, 'g'), ' ');
          if (stripped !== rest) used.add(a);
          rest = stripped;
        }
        for (const [re, what] of spec.banned) {
          if (re.test(rest)) hits.push(`${rel}:${i + 1}: ${what}: ${line.trim().slice(0, 100)}`);
        }
      });
    }
  }
  for (const a of spec.allow ?? []) {
    if (!used.has(a)) hits.push(`${a.file}: stale allowlist entry (${a.token.source} no longer used there); remove it`);
  }
  const mode = enforce.has(lang) ? 'enforced' : 'report only';
  console.log(`${lang} (${mode}): ${files} source files, ${hits.length} hits, ${(spec.allow ?? []).length} allowlisted`);
  for (const h of hits) console.log(`  ${h}`);
  for (const a of spec.allow ?? []) console.log(`  allowed in ${a.file}: ${a.why}`);
  if (hits.length && enforce.has(lang)) {
    failing++;
    console.log(`::error::the ${lang} wrapper reaches a crypto, X.509, ASN.1, CMS or JWS API; it must leave every such decision to aprv.wasm`);
  }
}
process.exit(failing ? 1 : 0);
