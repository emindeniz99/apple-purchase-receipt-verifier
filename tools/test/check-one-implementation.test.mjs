// tools/check-one-implementation.mjs against a scratch tree laid out like
// this repository, one file per wrapper language, holding every way past
// the gate a review has found: a comment marker inside a string, a block
// comment opened by a glob in prose, an import spelled with an attribute,
// an access level or a declaration kind, an interpolation inside a
// multi-line string, a `*` line that is code, a name inside a longer
// one. Each such line must be a hit. The whole-line comments beside them,
// which name the same APIs as prose, must not be.
//
//   node --test tools/test/check-one-implementation.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const check = join(dirname(fileURLToPath(import.meta.url)), '..', 'check-one-implementation.mjs');

// [line, true when the line must be a hit]
const HIT = true;
const NO = false;

const FILES = {
  'node/src/bypass.js': [
    [`const u = "http://x"; const c = require('node:crypto');`, HIT],
    ['// globs like src/*', NO],
    [`const d = require('node:crypto');`, HIT],
    ['/** doc */', NO],
    ['/* note */ const s = crypto.subtle;', HIT],
    ['const t = `', NO],
    [`// \${require('node:crypto').createHash('sha1')}`, HIT],
    ['`;', NO],
    ['const n = 2', NO],
    [`  * require('node:crypto').randomInt(2);`, HIT],
  ],
  'node/src/comments.js': [
    [`// require('node:crypto'), crypto.subtle`, NO],
    ['/* X509Certificate', NO],
    [' * createVerify, parseCertificate', NO],
    [' */', NO],
    ['/** verifyEs256 */', NO],
  ],
  'go/bypass.go': [
    ['package bypass', NO],
    ['var u = "https://a"; c, _ := x509.ParseCertificate(b)', HIT],
    ['// globs like src/*', NO],
    ['import "crypto/ecdsa"', HIT],
    ['/** doc */', NO],
    ['*p = x509.NewCertPool()', HIT],
    ['/* note */ import "encoding/asn1"', HIT],
  ],
  'go/comments.go': [
    ['// x509.ParseCertificate, "crypto/rsa"', NO],
    ['/* x509.SystemCertPool', NO],
    [' * CheckSignatureFrom', NO],
    [' */', NO],
  ],
  'java-wasm/src/main/java/x/Bypass.java': [
    ['String u = "http://x"; java.security.cert.CertificateFactory f = null;', HIT],
    ['// globs like src/*', NO],
    ['import javax.crypto.Cipher;', HIT],
    ['/** doc */', NO],
    ['/* note */ org.bouncycastle.asn1.ASN1Object o = null;', HIT],
    ['/* a */', NO],
    ['* javax.crypto.Cipher.getInstance("AES").getBlockSize();', HIT],
  ],
  'java-wasm/src/main/java/x/Comments.java': [
    ['// org.bouncycastle, java.security.Signature', NO],
    ['/** javax.crypto */', NO],
    ['/**', NO],
    [' * sun.security', NO],
    [' */', NO],
  ],
  'dotnet/src/X/Bypass.cs': [
    ['var u = "http://x"; var e = ECDsa.Create();', HIT],
    ['// globs like src/*', NO],
    ['using System.Formats.Asn1;', HIT],
    ['/** doc */', NO],
    ['var s = $"""', NO],
    ['// {new SignedCms()}', HIT],
    ['""";', NO],
  ],
  'dotnet/src/X/Comments.cs': [
    ['// X509Chain, RSACryptoServiceProvider', NO],
    ['/// <summary>SignedCms and VerifyData</summary>', NO],
    ['/* ECDsa', NO],
    [' * System.Security.Cryptography.Pkcs', NO],
    [' */', NO],
  ],
  'php/src/Bypass.php': [
    ['<?php', NO],
    [`$u = 'http://x'; openssl_verify($a, $b, $c);`, HIT],
    ['// globs like src/*', NO],
    ['sodium_crypto_sign_verify_detached($a, $b, $c);', HIT],
    ['/** doc */', NO],
    ['#[Pure] function f($a, $b, $c) { return openssl_verify($a, $b, $c); }', HIT],
    ['$x = "a#b"; gmp_powm(1, 2, 3);', HIT],
    ['$s = <<<EOT', NO],
    ['# {$fn(openssl_verify($a, $b, $c))}', HIT],
    ['EOT;', NO],
  ],
  'php/src/Comments.php': [
    ['<?php', NO],
    ['// openssl_verify($a, $b, $c)', NO],
    ['# openssl_sign($a, $b, $c)', NO],
    ['/* phpseclib', NO],
    [` * hash_hmac('sha256', $a, $b)`, NO],
    [' */', NO],
  ],
  'ruby/lib/bypass.rb': [
    ['s = "a#b"; c = OpenSSL::X509::Certificate.new(der)', HIT],
    ['t = "#{OpenSSL::PKey.read(k)}"', HIT],
    ['u = <<~S', NO],
    [`  #{OpenSSL::Digest.new('SHA1')}`, HIT],
    ['S', NO],
    ['MyOpenSSL.run', HIT],
  ],
  'ruby/lib/comments.rb': [
    ['# OpenSSL::X509, PKCS7, ASN1', NO],
    ['  # require "openssl"', NO],
    ['# Signature', NO],
  ],
  'swift/Sources/X/Bypass.swift': [
    ['let u = "http://x"; let t: SecTrust? = nil', HIT],
    ['// globs like src/*', NO],
    ['public import Crypto', HIT],
    ['/** doc */', NO],
    ['internal import SwiftASN1', HIT],
    ['@preconcurrency import Security', HIT],
    ['@_exported import X509', HIT],
    ['import struct CryptoKit.SHA256', HIT],
    ['import CryptoSwift', HIT],
    ['import SecurityFoundation', HIT],
    ['@_implementationOnly import _CryptoExtras', HIT],
    ['import CommonCrypto', HIT],
    ['let m = """', NO],
    ['// \\(SecCertificateCreateWithData(nil, d))', HIT],
    ['"""', NO],
    ['let r = #"""', NO],
    ['// \\#(SecTrustEvaluateWithError(t, nil))', HIT],
    ['"""#', NO],
  ],
  'swift/Sources/X/Comments.swift': [
    ['// import Security', NO],
    ['/// SecTrust', NO],
    ['/* import CryptoKit', NO],
    [' * SecCertificate', NO],
    [' */', NO],
  ],
  'python/apple_purchase_receipt_verifier/bypass.py': [
    ['x = "a#b"; import cryptography', HIT],
    ['import os, hmac', HIT],
    ['import os as o, ssl', HIT],
    ['from jose import jwt', HIT],
    ['try: import ssl', HIT],
    ['import hmac_free_helper', NO],
  ],
  'python/apple_purchase_receipt_verifier/comments.py': [
    ['# import ssl', NO],
    ['    #from cryptography import x509', NO],
  ],
};

test('every bypass is a hit and no whole-line comment is', () => {
  const root = mkdtempSync(join(tmpdir(), 'aprv-one-implementation-'));
  try {
    for (const [file, lines] of Object.entries(FILES)) {
      mkdirSync(dirname(join(root, file)), { recursive: true });
      writeFileSync(join(root, file), `${lines.map(([line]) => line).join('\n')}\n`);
    }
    const result = spawnSync(process.execPath, [check, '--enforce', 'all', '--root', root], { encoding: 'utf8' });
    const output = `${result.stdout}${result.stderr}`;
    assert.equal(result.status, 1, output);
    const hits = new Set([...output.matchAll(/^ {2}(\S+?):(\d+): /gm)].map(([, file, line]) => `${file}:${line}`));
    for (const [file, lines] of Object.entries(FILES)) {
      lines.forEach(([line, hit], i) => {
        assert.equal(hits.has(`${file}:${i + 1}`), hit, `${file}:${i + 1} ${hit ? 'must' : 'must not'} be a hit: ${line}\n${output}`);
      });
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
