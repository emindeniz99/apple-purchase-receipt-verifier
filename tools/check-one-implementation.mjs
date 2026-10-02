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
//   node tools/check-one-implementation.mjs [--enforce <all|lang,lang,...>]
//
// Lists every hit, per language. Without --enforce it only reports; with
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
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

// Where each wrapper's shipped source lives, the files that count, the
// comment syntax stripped before matching (so prose may name what the code
// avoids), and the APIs it must not reach.
const LANGS = {
  node: {
    dirs: ['node/src'],
    files: /\.(m?[jt]s|cjs|cts|mts)$/,
    comments: 'c',
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
    banned: [
      [/^\s*(from|import)\s+(cryptography|OpenSSL|asn1crypto|pyasn1|ecdsa|Crypto|Cryptodome|jwt|jose)\b/m, 'a Python crypto/ASN.1 library'],
      [/^\s*(from|import)\s+(ssl|hmac)\b/m, 'ssl or hmac'],
    ],
  },
  go: {
    dirs: ['go'],
    files: /(?<!_test)\.go$/,
    skipDirs: ['go/tools', 'go/fuzz', 'go/bench', 'go/examples', 'go/cmd'],
    comments: 'c',
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
      [/^\s*(@_implementationOnly\s+)?import\s+(Crypto|_CryptoExtras|CryptoKit|X509|SwiftASN1|Security|CommonCrypto)\b/m, 'a Swift crypto/X.509/ASN.1 module'],
      [/\bSec(Trust|Certificate)/, 'the Security framework\'s trust or certificate API'],
    ],
    comments: 'c',
  },
  ruby: {
    dirs: ['ruby/lib'],
    files: /\.rb$/,
    comments: 'hash',
    banned: [
      [/\bOpenSSL\b|require\s*\(?\s*['"]openssl['"]/, 'OpenSSL'],
      [/require\s*\(?\s*['"](jwt|jose|json\/jwt)['"]/, 'a Ruby JWT library'],
      [/\bX509\b|\bPKCS7\b|\bASN1\b|\bECDSA\b|\bx5c\b|base64url/i, 'an X.509, PKCS #7, ASN.1, ECDSA or JWS name'],
      [/\bCMS\b|Signature/, 'a CMS or signature name'],
    ],
  },
  dotnet: {
    dirs: ['dotnet/src'],
    files: /\.cs$/,
    comments: 'c',
    banned: [
      [/System\.Security\.Cryptography\.(Pkcs|X509Certificates)|System\.Formats\.Asn1|Asn(Reader|Writer|Decoder)|\bX509Certificate2?\b|X509Chain|SignedCms|SignerInfo/, '.NET X.509/CMS/ASN.1'],
      [/\b(ECDsa|RSA|DSA)\s*\.\s*Create\b|ECDsa|\bRSA(Cng|OpenSsl)?\b|RSACryptoServiceProvider|Verify(Data|Hash)|Org\.BouncyCastle/, '.NET signature verification'],
    ],
    allow: [
      { file: 'dotnet/src/ApplePurchaseReceiptVerifier/Config.cs', token: /using System\.Security\.Cryptography\.X509Certificates;|\bX509Certificate2\b/g, why: 'Config.Roots and Config.Builder.Roots take X509Certificate2 (the 0.7 API); only its RawData, the DER, reaches the module' },
      { file: 'dotnet/src/ApplePurchaseReceiptVerifier/Internal/Certificates.cs', token: /using System\.Security\.Cryptography\.X509Certificates;|\bX509Certificate2\b/g, why: "wraps DER in an X509Certificate2 for Config.Roots above; no chain, no key, no signature" },
    ],
  },
  php: {
    dirs: ['php/src'],
    files: /\.php$/,
    comments: 'c',
    banned: [
      [/\bopenssl_[a-z0-9_]+\s*\(/i, 'openssl_*'],
      [/\bsodium_crypto|phpseclib|\\?FG\\ASN1|Firebase\\JWT|\bJose\\/i, 'a PHP crypto/ASN.1/JWT library'],
      // Functions, not methods: `->name(` and `::name(` are a class's own.
      [/(?<![>:$\w])(gmp_\w+|bcpowmod|hash_hmac\w*|mcrypt_\w+)\s*\(/i, 'a big-number, HMAC or mcrypt function'],
    ],
  },
  'java-wasm': {
    comments: 'c',
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
      { file: 'java-wasm/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/Config.java', token: /import java\.security\.cert\.X509Certificate;/, why: 'Config.roots() holds X509Certificate (the 0.7 API); only getEncoded(), the DER, reaches the module' },
      { file: 'java-wasm/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/AppleRootCerts.java', token: /import java\.security\.cert\.(CertificateException|CertificateFactory|X509Certificate);/, why: 'AppleRootCerts returns the three bundled roots as X509Certificate for the 0.7 API; the module holds its own copy and decides trust' },
      { file: 'java-wasm/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/WasmVerifier.java', token: /import java\.security\.cert\.(CertificateEncodingException|X509Certificate);/, why: "takes each root's getEncoded() DER for the Endive engine's init; nothing is parsed or checked" },
      { file: 'java-wasm/src/main/java/io/github/emindeniz99/applepurchasereceiptverifier/ServerSources.java', token: /import java\.security\.cert\.(CertificateEncodingException|X509Certificate);/, why: "takes each root's getEncoded() DER for the server engine's roots file; nothing is parsed or checked" },
    ],
  },
};

// Comments become spaces, newlines kept, so line numbers still match. A
// comment marker inside a string literal is taken for a comment too; that
// can only hide a hit on the rest of that line, never invent one.
const STRIP = {
  c: (text) => text.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' ')).replace(/\/\/.*$/gm, ''),
  hash: (text) => text.replace(/#.*$/gm, ''),
};

const SKIP = /(^|\/)(tests?|__tests__|spec|fuzz|bench|benches|samples?|examples?|generated|node_modules|dist|build|target|vendor|\.build)(\/|$)/;

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* walk(path);
    else yield path;
  }
}

const args = process.argv.slice(2);
let enforce = new Set();
if (args[0] === '--enforce') {
  if (!args[1]) {
    console.error('usage: node tools/check-one-implementation.mjs [--enforce <all|lang,lang,...>]');
    process.exit(2);
  }
  enforce = new Set(args[1] === 'all' ? Object.keys(LANGS) : args[1].split(','));
  for (const l of enforce) {
    if (!LANGS[l]) {
      console.error(`check-one-implementation: unknown language ${l}; known: ${Object.keys(LANGS).join(', ')}`);
      process.exit(2);
    }
  }
} else if (args.length) {
  console.error('usage: node tools/check-one-implementation.mjs [--enforce <all|lang,lang,...>]');
  process.exit(2);
}

let failing = 0;
const used = new Set();
for (const [lang, spec] of Object.entries(LANGS)) {
  const hits = [];
  let files = 0;
  for (const dir of spec.dirs) {
    const abs = join(ROOT, dir);
    if (!existsSync(abs)) continue;
    for (const path of walk(abs)) {
      const rel = relative(ROOT, path);
      if (!spec.files.test(rel) || SKIP.test(relative(abs, path)) || spec.skipDirs?.some((d) => rel.startsWith(`${d}/`))) continue;
      files++;
      const allowed = (spec.allow ?? []).filter((a) => a.file === rel);
      const source = readFileSync(path, 'utf8');
      const lines = (spec.comments ? STRIP[spec.comments](source) : source).split('\n');
      lines.forEach((line, i) => {
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
