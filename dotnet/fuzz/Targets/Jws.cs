using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ApplePurchaseReceiptVerifier.Jws;

namespace ApplePurchaseReceiptVerifier.Fuzz.Targets
{
    /// <summary>
    /// The StoreKit 2 path: compact-JWS split, strict base64url, JSON header
    /// and payload, the <c>x5c</c> certificates, the chain, the ES256
    /// signature, then the claim checks of all three public entry points.
    /// </summary>
    /// <remarks>
    /// Same invariants as the Go port's <c>FuzzVerifyTransaction</c>: nothing
    /// but a <see cref="VerificationException"/> escapes any of the three, and
    /// a JWS that <c>VerifyRaw</c> accepts under the generated fixture root
    /// must be refused under Apple's real JWS roots — otherwise the anchors
    /// are not what decided it.
    /// </remarks>
    internal sealed class Jws : IDisposable
    {
        private readonly JwsVerifier _fixture;
        private readonly JwsVerifier _unrelated;
        private readonly X509Certificate2 _root;

        internal Jws()
        {
            _root = Fixtures.JwsRoot();
            AppleEnvironment[] environments =
            {
                AppleEnvironment.Production,
                AppleEnvironment.Sandbox,
                AppleEnvironment.Xcode,
                AppleEnvironment.LocalTesting,
            };
            _fixture = new JwsVerifier(
                new[] { _root }, "com.example.app", environments, appAppleId: 1234567890);
            _unrelated = new JwsVerifier(
                AppleRootCertificates.JwsRoots(), "com.example.app", environments, appAppleId: 1234567890);
        }

        internal void Run(ReadOnlySpan<byte> data)
        {
            string jws;
            try
            {
                jws = new UTF8Encoding(false, true).GetString(data.ToArray());
            }
            catch (DecoderFallbackException)
            {
                return;
            }

            try
            {
                _fixture.VerifyTransaction(jws);
            }
            catch (Exception e)
            {
                Invariant.Contained("VerifyTransaction", e);
            }

            try
            {
                _fixture.VerifyAppTransaction(jws);
            }
            catch (Exception e)
            {
                Invariant.Contained("VerifyAppTransaction", e);
            }

            try
            {
                _fixture.VerifyRaw(jws);
            }
            catch (Exception e)
            {
                Invariant.Contained("VerifyRaw", e);
                return;
            }

            try
            {
                _unrelated.VerifyRaw(jws);
            }
            catch (VerificationException)
            {
                return;
            }

            throw new InvariantException(
                "this input verifies against Apple's roots too, "
                + "so the anchors are not being enforced");
        }

        public void Dispose()
        {
            _fixture.Dispose();
            _unrelated.Dispose();
            _root.Dispose();
        }
    }
}
