#!/usr/bin/env node
// The one-implementation gate (ARCHITECTURE.md §9): no wrapper around
// aprv.wasm may parse, verify or decide anything itself, so no non-Java
// wrapper may call a crypto, X.509, ASN.1 or CMS API outside its tests.
//
//   node tools/check-one-implementation.mjs [--enforce <all|lang,lang,...>]
//
// Lists every hit, per language. Without --enforce it only reports (the
// hand-written 0.7 verifiers are still in the tree until MIGRATION.md
// Phase 7 deletes them); with --enforce it exits 1 on a hit in any listed
// language, so each wrapper's gate can be turned on as its lane lands and
// `all` once Phase 7 is done.
//
// What stays allowed, because a wrapper needs it without deciding trust:
// a CSPRNG for the module's random-get import, and a SHA-256 to check a
// copy of aprv.wasm or a downloaded aprv binary against its pin.
//
// Out of scope by design: the Java main artifact (java/, the independent
// implementation, DECISIONS.md R33), the Rust core, every test, fuzz,
// bench and sample directory, and generated bindings.
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

// Where each wrapper's shipped source lives, the files that count, and the
// APIs it must not reach.
const LANGS = {
  node: {
    dirs: ['node/src'],
    files: /\.(m?[jt]s|cjs|cts|mts)$/,
    banned: [
      [/\bfrom\s+['"](node:)?crypto['"]|require\(\s*['"](node:)?crypto['"]\s*\)|import\(\s*['"](node:)?crypto['"]\s*\)/, 'node:crypto'],
      [/\bcrypto\.subtle\b|\bSubtleCrypto\b/, 'WebCrypto subtle'],
      [/['"](asn1js|pkijs|jose|node-forge|@peculiar\/[^'"]+|jsrsasign)['"]/, 'a JS crypto/ASN.1 library'],
    ],
  },
  python: {
    dirs: ['python/apple_purchase_receipt_verifier', 'python/src'],
    files: /\.py$/,
    banned: [
      [/^\s*(from|import)\s+(cryptography|OpenSSL|asn1crypto|pyasn1|ecdsa|Crypto|Cryptodome|jwt|jose)\b/m, 'a Python crypto/ASN.1 library'],
      [/^\s*(from|import)\s+ssl\b/m, 'ssl'],
    ],
  },
  go: {
    dirs: ['go'],
    files: /(?<!_test)\.go$/,
    skipDirs: ['go/tools', 'go/fuzz', 'go/bench', 'go/examples', 'go/cmd'],
    banned: [
      [/"(crypto\/(x509|ecdsa|rsa|elliptic|ecdh|ed25519|tls|dsa)|encoding\/asn1|golang\.org\/x\/crypto\/[^"]*|github\.com\/[^"]*\/(jwt|jose|pkcs7)[^"]*)"/, 'a Go crypto/X.509/ASN.1 package'],
    ],
  },
  swift: {
    dirs: ['swift/Sources'],
    files: /\.swift$/,
    banned: [
      [/^\s*(@_implementationOnly\s+)?import\s+(Crypto|_CryptoExtras|CryptoKit|X509|SwiftASN1|Security|CommonCrypto)\b/m, 'a Swift crypto/X.509/ASN.1 module'],
    ],
  },
  ruby: {
    dirs: ['ruby/lib'],
    files: /\.rb$/,
    banned: [
      [/\bOpenSSL::|require\s*\(?\s*['"]openssl['"]/, 'OpenSSL'],
      [/require\s*\(?\s*['"](jwt|jose|json\/jwt)['"]/, 'a Ruby JWT library'],
    ],
  },
  dotnet: {
    dirs: ['dotnet/src'],
    files: /\.cs$/,
    banned: [
      [/System\.Security\.Cryptography\.(Pkcs|X509Certificates)|System\.Formats\.Asn1|\bAsnReader\b|\bX509Certificate2?\b|\bSignedCms\b/, '.NET X.509/CMS/ASN.1'],
      [/\b(ECDsa|RSA|DSA)\s*\.\s*Create\b|\bECDsa(Cng|OpenSsl)?\b|\bRSA(Cng|OpenSsl|CryptoServiceProvider)\b|Org\.BouncyCastle/, '.NET signature verification'],
    ],
  },
  php: {
    dirs: ['php/src'],
    files: /\.php$/,
    banned: [
      [/\bopenssl_[a-z0-9_]+\s*\(/, 'openssl_*'],
      [/\bsodium_crypto_sign|phpseclib|\\?FG\\ASN1|Firebase\\JWT|\bJose\\/, 'a PHP crypto/ASN.1/JWT library'],
    ],
  },
  'java-wasm': {
    dirs: ['java-wasm/src/main'],
    files: /\.java$/,
    banned: [
      [/\borg\.bouncycastle\b|\bjava\.security\.cert\b|\bjava\.security\.Signature\b|\bjavax\.crypto\b|\bjava\.security\.KeyFactory\b|\bsun\.security\b/, 'a Java crypto/X.509 API'],
    ],
  },
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
      const lines = readFileSync(path, 'utf8').split('\n');
      lines.forEach((line, i) => {
        for (const [re, what] of spec.banned) {
          if (re.test(line)) hits.push(`${rel}:${i + 1}: ${what}: ${line.trim().slice(0, 100)}`);
        }
      });
    }
  }
  const mode = enforce.has(lang) ? 'enforced' : 'report only';
  console.log(`${lang} (${mode}): ${files} source files, ${hits.length} hits`);
  for (const h of hits) console.log(`  ${h}`);
  if (hits.length && enforce.has(lang)) {
    failing++;
    console.log(`::error::the ${lang} wrapper reaches a crypto, X.509 or ASN.1 API; it must leave every such decision to aprv.wasm`);
  }
}
process.exit(failing ? 1 : 0);
