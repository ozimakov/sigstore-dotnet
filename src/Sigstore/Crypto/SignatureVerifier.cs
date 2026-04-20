using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigstore.Exceptions;

namespace Sigstore.Crypto;

/// <summary>
/// Verifies artifact signatures using only <see cref="System.Security.Cryptography"/> primitives.
/// Signature algorithms are implied by the leaf certificate public key (PKIX).
/// </summary>
public sealed class SignatureVerifier : ISignatureVerifier
{
    /// <inheritdoc />
    public void VerifyArtifactSignature(
        X509Certificate2 leafCertificate,
        ReadOnlySpan<byte> artifact,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm)
    {
        PublicKey publicKey = leafCertificate.PublicKey;
        if (publicKey.Oid?.Value == "1.2.840.10045.2.1")
        {
            using ECDsa? ecdsa = leafCertificate.GetECDsaPublicKey();
            if (ecdsa is null)
            {
                throw new SignatureVerificationException("Step 8 (signature): ECDSA public key could not be loaded from the leaf certificate.");
            }

            if (!ecdsa.VerifyData(artifact, signature, hashAlgorithm))
            {
                throw new SignatureVerificationException("Step 8 (signature): ECDSA signature verification failed for the artifact.");
            }

            return;
        }

        if (publicKey.Oid?.Value == "1.2.840.113549.1.1.1")
        {
            using RSA? rsa = leafCertificate.GetRSAPublicKey();
            if (rsa is null)
            {
                throw new SignatureVerificationException("Step 8 (signature): RSA public key could not be loaded from the leaf certificate.");
            }

            RSASignaturePadding padding = RSASignaturePadding.Pss;
            if (!rsa.VerifyData(artifact, signature, hashAlgorithm, padding))
            {
                if (!rsa.VerifyData(artifact, signature, hashAlgorithm, RSASignaturePadding.Pkcs1))
                {
                    throw new SignatureVerificationException("Step 8 (signature): RSA signature verification failed for the artifact.");
                }
            }

            return;
        }

        throw new SignatureVerificationException($"Step 8 (signature): unsupported public key algorithm OID '{publicKey.Oid?.Value}'.");
    }
}

/// <summary>
/// Artifact signature verification against a leaf certificate.
/// </summary>
public interface ISignatureVerifier
{
    /// <summary>
    /// Verifies <paramref name="signature"/> over <paramref name="artifact"/> using the leaf certificate public key.
    /// </summary>
    /// <param name="leafCertificate">Leaf signing certificate.</param>
    /// <param name="artifact">Raw artifact bytes.</param>
    /// <param name="signature">Signature bytes from the bundle.</param>
    /// <param name="hashAlgorithm">Hash algorithm used with the signature scheme.</param>
    void VerifyArtifactSignature(
        X509Certificate2 leafCertificate,
        ReadOnlySpan<byte> artifact,
        ReadOnlySpan<byte> signature,
        HashAlgorithmName hashAlgorithm);
}
