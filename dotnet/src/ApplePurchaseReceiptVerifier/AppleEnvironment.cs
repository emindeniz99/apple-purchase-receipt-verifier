using System;

namespace ApplePurchaseReceiptVerifier
{
    /// <summary>
    /// Apple's two verifyReceipt server environments: the one
    /// <see cref="IVerifier.VerifyReceiptEndpoint"/> imitates, and the one a
    /// verified payload states (<see cref="ReceiptPayload.Environment"/>,
    /// <see cref="JsonPayload.Environment"/>).
    /// </summary>
    /// <remarks>
    /// <para>Named <c>AppleEnvironment</c> rather than <c>Environment</c> because
    /// <see cref="System.Environment"/> exists and an unqualified
    /// <c>Environment</c> in a consumer's file is a resolution trap.</para>
    /// <para>0.7 drops the 0.6 <c>Xcode</c> and <c>LocalTesting</c> members: they
    /// only ever named JWS <c>environment</c> strings, such payloads are not
    /// Apple-signed and fail the chain check regardless, and the caller now
    /// reads that string from the verified JSON itself.</para>
    /// <para>0.8 drops the 0.7 helpers <c>AppleEnvironments.FromReceiptType</c>
    /// and <c>AppleEnvironments.FromJwsEnvironment</c>: the verifier states
    /// the environment on the payload instead.</para>
    /// </remarks>
    public enum AppleEnvironment
    {
        /// <summary>Apple's production verifyReceipt URL.</summary>
        Production,

        /// <summary>Apple's sandbox verifyReceipt URL.</summary>
        Sandbox,
    }
}
