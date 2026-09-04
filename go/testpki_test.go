package applereceipt_test

// A miniature Apple-shaped PKI and a miniature DER writer, so the native
// tests can build the inputs no fixture provides: a receipt with an
// unsupported digest, a chain whose intermediate is not a CA, a JWS whose
// x5c holds two hundred certificates.
//
// This is test-only scaffolding. The library never encodes anything.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	oidAppleLeaf = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 11, 1}
	oidAppleWWDR = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 2, 1}
	oidPKCS7Data = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidPKCS7Sign = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA1Hash  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA512    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidMsgDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidContentTy = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
)

type testCert struct {
	cert *x509.Certificate
	der  []byte
	key  crypto.Signer
}

type certSpec struct {
	commonName string
	isCA       bool
	// noBasicConstraints omits the basicConstraints extension entirely.
	noBasicConstraints bool
	// keyUsage is set only when nonZero is true, so "no keyUsage
	// extension" stays expressible.
	keyUsage      x509.KeyUsage
	setKeyUsage   bool
	markerOIDs    []asn1.ObjectIdentifier
	notBefore     time.Time
	notAfter      time.Time
	rsa           bool
	signatureAlgo x509.SignatureAlgorithm
	serial        *big.Int
	// key reuses an existing key instead of taking one from the pool, so
	// two certificates can share key material under different names.
	key crypto.Signer
}

var serialCounter int64 = 1000

func nextSerial() *big.Int {
	serialCounter++
	return big.NewInt(serialCounter)
}

// RSA key generation dominates the runtime of this suite, so a small
// pool is generated once and handed out round-robin. The keys stay
// distinct enough that no two certificates in one chain share one, which
// is all any test here depends on.
var rsaKeyPool = sync.OnceValue(func() []*rsa.PrivateKey {
	const poolSize = 8
	keys := make([]*rsa.PrivateKey, poolSize)
	var wg sync.WaitGroup
	for i := range keys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			keys[i] = key
		}(i)
	}
	wg.Wait()
	return keys
})

var rsaKeyCursor atomic.Uint64

func newKey(t *testing.T, useRSA bool) crypto.Signer {
	t.Helper()
	if useRSA {
		pool := rsaKeyPool()
		return pool[int(rsaKeyCursor.Add(1))%len(pool)]
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// issueCert issues a certificate. parent nil means self-signed.
func issueCert(t *testing.T, spec certSpec, parent *testCert) *testCert {
	t.Helper()
	key := spec.key
	if key == nil {
		key = newKey(t, spec.rsa)
	}
	notBefore := spec.notBefore
	if notBefore.IsZero() {
		// Wide by default so a test that pins a historical signing date
		// is testing that rule and not the scaffolding's validity window.
		notBefore = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	notAfter := spec.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(10 * 365 * 24 * time.Hour)
	}
	serial := spec.serial
	if serial == nil {
		serial = nextSerial()
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: spec.commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  spec.isCA,
		BasicConstraintsValid: !spec.noBasicConstraints,
		SignatureAlgorithm:    spec.signatureAlgo,
	}
	if spec.setKeyUsage {
		template.KeyUsage = spec.keyUsage
	} else if spec.isCA {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	for _, oid := range spec.markerOIDs {
		template.ExtraExtensions = append(template.ExtraExtensions,
			pkix.Extension{Id: oid, Critical: false, Value: []byte{0x05, 0x00}})
	}
	issuerCert := template
	var issuerKey crypto.Signer = key
	if parent != nil {
		issuerCert = parent.cert
		issuerKey = parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuerCert, key.Public(), issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{cert: parsed, der: der, key: key}
}

// appleShapedJWSPKI is root -> WWDR-marked intermediate -> leaf-marked
// leaf, all ECDSA, matching the shape Apple's JWS chains have.
type jwsPKI struct {
	root, intermediate, leaf *testCert
}

func newJWSPKI(t *testing.T) jwsPKI {
	t.Helper()
	root := issueCert(t, certSpec{commonName: "Test Apple Root", isCA: true}, nil)
	intermediate := issueCert(t, certSpec{
		commonName: "Test WWDR", isCA: true, markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
	}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Test Leaf", markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, intermediate)
	return jwsPKI{root: root, intermediate: intermediate, leaf: leaf}
}

func (p jwsPKI) anchorSlice() []*x509.Certificate { return []*x509.Certificate{p.root.cert} }

func (p jwsPKI) sign(t *testing.T, payload map[string]any) string {
	t.Helper()
	return signJWS(t, p.leaf, [][]byte{p.leaf.der, p.intermediate.der, p.root.der}, payload)
}

func signJWS(t *testing.T, leaf *testCert, x5c [][]byte, payload map[string]any) string {
	t.Helper()
	chain := make([]string, 0, len(x5c))
	for _, der := range x5c {
		chain = append(chain, base64.StdEncoding.EncodeToString(der))
	}
	header := map[string]any{"alg": "ES256", "x5c": chain}
	headerB64 := jsonSegment(t, header)
	payloadB64 := jsonSegment(t, payload)
	key, ok := leaf.key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("signJWS needs an ECDSA leaf key")
	}
	digest := sha256.Sum256([]byte(headerB64 + "." + payloadB64))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return headerB64 + "." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func jsonSegment(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// --- a minimal DER writer ------------------------------------------------

func tlv(tag byte, contents []byte) []byte {
	var header []byte
	switch n := len(contents); {
	case n < 0x80:
		header = []byte{tag, byte(n)}
	case n < 0x100:
		header = []byte{tag, 0x81, byte(n)}
	case n < 0x10000:
		header = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	default:
		header = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(header, contents...)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func derSequence(parts ...[]byte) []byte { return tlv(0x30, concat(parts...)) }
func derSet(parts ...[]byte) []byte      { return tlv(0x31, concat(parts...)) }
func derContext0(parts ...[]byte) []byte { return tlv(0xa0, concat(parts...)) }
func derOctetString(b []byte) []byte     { return tlv(0x04, b) }
func derUTF8String(s string) []byte      { return tlv(0x0c, []byte(s)) }
func derIA5String(s string) []byte       { return tlv(0x16, []byte(s)) }
func derNull() []byte                    { return []byte{0x05, 0x00} }

func derInteger(value *big.Int) []byte {
	encoded, err := asn1.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func derInt(value int64) []byte { return derInteger(big.NewInt(value)) }

func derOID(oid asn1.ObjectIdentifier) []byte {
	encoded, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	return encoded
}

func algorithmIdentifier(oid asn1.ObjectIdentifier) []byte {
	return derSequence(derOID(oid), derNull())
}

// --- receipt payloads ----------------------------------------------------

func receiptAttribute(kind *big.Int, value []byte) []byte {
	return derSequence(derInteger(kind), derInt(1), derOctetString(value))
}

func attr(kind int64, value []byte) []byte {
	return receiptAttribute(big.NewInt(kind), value)
}

func receiptPayload(attributes ...[]byte) []byte { return derSet(attributes...) }

// standardReceiptAttributes is the attribute set the happy-path
// synthesized receipt carries.
func standardReceiptAttributes(bundleID, receiptType string, creation time.Time) [][]byte {
	return [][]byte{
		attr(0, derUTF8String(receiptType)),
		attr(2, derUTF8String(bundleID)),
		attr(3, derUTF8String("1.2.3")),
		attr(4, []byte{1, 2, 3, 4, 5, 6, 7, 8}),
		attr(12, derIA5String(creation.UTC().Format(time.RFC3339))),
		attr(19, derUTF8String("1.0")),
	}
}

// --- CMS SignedData ------------------------------------------------------

type cmsSpec struct {
	content      []byte
	signer       *testCert
	certificates [][]byte
	digestOID    asn1.ObjectIdentifier
	// withSignedAttrs signs over a signedAttrs SET carrying a
	// messageDigest, the shape genuine Apple receipts use.
	withSignedAttrs bool
	// corruptMessageDigest flips the messageDigest attribute.
	corruptMessageDigest bool
	// omitSignerInfos produces a SignedData with an empty SignerInfo set.
	omitSignerInfos bool
	// omitContent produces an encapContentInfo with no [0] eContent.
	omitContent bool
	// signerSerial overrides the SignerInfo serial, so the "signer not
	// embedded" path can be reached.
	signerSerial *big.Int
	// badSignature corrupts the signature bytes.
	badSignature bool
}

func buildCMS(t *testing.T, spec cmsSpec) []byte {
	t.Helper()
	digestOID := spec.digestOID
	if digestOID == nil {
		digestOID = oidSHA256
	}
	hasher, cryptoHash := hasherFor(t, digestOID)

	encap := derSequence(derOID(oidPKCS7Data))
	if !spec.omitContent {
		encap = derSequence(derOID(oidPKCS7Data), derContext0(derOctetString(spec.content)))
	}

	serial := spec.signerSerial
	if serial == nil {
		serial = spec.signer.cert.SerialNumber
	}
	signerIdentifier := derSequence(spec.signer.cert.RawIssuer, derInteger(serial))

	var signedAttrsField []byte
	signed := spec.content
	if spec.withSignedAttrs {
		digest := hasher(spec.content)
		if spec.corruptMessageDigest {
			digest[0] ^= 0xff
		}
		attributes := concat(
			derSequence(derOID(oidContentTy), derSet(derOID(oidPKCS7Data))),
			derSequence(derOID(oidMsgDigest), derSet(derOctetString(digest))),
		)
		signedAttrsField = tlv(0xa0, attributes)
		signed = tlv(0x31, attributes) // the SET form the signature covers
	}

	key, ok := spec.signer.key.(*rsa.PrivateKey)
	var signature []byte
	if ok {
		sum := hasher(signed)
		var err error
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, cryptoHash, sum)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		// A non-RSA signer: the bytes are junk on purpose, because the
		// library must reject the key type before it ever looks at them.
		signature = []byte{1, 2, 3, 4}
	}
	if spec.badSignature && len(signature) > 0 {
		signature[0] ^= 0xff
	}

	signerInfoParts := [][]byte{derInt(1), signerIdentifier, algorithmIdentifier(digestOID)}
	if signedAttrsField != nil {
		signerInfoParts = append(signerInfoParts, signedAttrsField)
	}
	signerInfoParts = append(signerInfoParts,
		algorithmIdentifier(oidRSA), derOctetString(signature))
	signerInfo := derSequence(signerInfoParts...)

	signerInfos := derSet(signerInfo)
	if spec.omitSignerInfos {
		signerInfos = derSet()
	}

	signedData := derSequence(
		derInt(1),
		derSet(algorithmIdentifier(digestOID)),
		encap,
		derContext0(concat(spec.certificates...)),
		signerInfos,
	)
	return derSequence(derOID(oidPKCS7Sign), derContext0(signedData))
}

func hasherFor(t *testing.T, oid asn1.ObjectIdentifier) (func([]byte) []byte, crypto.Hash) {
	t.Helper()
	switch {
	case oid.Equal(oidSHA1Hash):
		return func(b []byte) []byte { sum := sha1.Sum(b); return sum[:] }, crypto.SHA1
	case oid.Equal(oidSHA256):
		return func(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }, crypto.SHA256
	default:
		// An unsupported digest still needs bytes to sign; SHA-256 keeps
		// the structure well-formed so the digest OID is what is tested.
		return func(b []byte) []byte { sum := sha256.Sum256(b); return sum[:] }, crypto.SHA256
	}
}

// receiptPKI is root -> WWDR intermediate -> receipt-signing leaf, all
// RSA, matching the shape a legacy Apple receipt chain has.
type receiptPKI struct {
	root, intermediate, leaf *testCert
}

func newReceiptPKI(t *testing.T) receiptPKI {
	t.Helper()
	root := issueCert(t, certSpec{commonName: "Test Apple Inc Root", isCA: true, rsa: true}, nil)
	intermediate := issueCert(t, certSpec{
		commonName: "Test Receipt WWDR", isCA: true, rsa: true,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleWWDR},
	}, root)
	leaf := issueCert(t, certSpec{
		commonName: "Test Receipt Signing", rsa: true,
		markerOIDs: []asn1.ObjectIdentifier{oidAppleLeaf},
	}, intermediate)
	return receiptPKI{root: root, intermediate: intermediate, leaf: leaf}
}

func (p receiptPKI) anchors() []*x509.Certificate { return []*x509.Certificate{p.root.cert} }

func (p receiptPKI) embedded() [][]byte { return [][]byte{p.leaf.der, p.intermediate.der} }

// receipt builds a well-formed signed receipt from this PKI.
func (p receiptPKI) receipt(t *testing.T, attributes ...[]byte) []byte {
	t.Helper()
	if len(attributes) == 0 {
		attributes = standardReceiptAttributes("com.example.app", "ProductionSandbox", time.Now())
	}
	return buildCMS(t, cmsSpec{
		content:         receiptPayload(attributes...),
		signer:          p.leaf,
		certificates:    p.embedded(),
		withSignedAttrs: true,
	})
}
