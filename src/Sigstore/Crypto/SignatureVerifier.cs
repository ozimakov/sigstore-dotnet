using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Sigstore.Exceptions;

namespace Sigstore.Crypto;

/// <summary>
/// Verifies artifact signatures using BCL primitives and BouncyCastle (for Ed25519).
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

            // Try DER format first (Sigstore default), fall back to IEEE P1363
            if (!ecdsa.VerifyData(artifact, signature, hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence) &&
                !ecdsa.VerifyData(artifact, signature, hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
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

        if (publicKey.Oid?.Value == "1.3.101.112") // Ed25519
        {
            try
            {
                byte[] spki = leafCertificate.PublicKey.ExportSubjectPublicKeyInfo();
                Ed25519PublicKeyParameters pubKey = (Ed25519PublicKeyParameters)PublicKeyFactory.CreateKey(spki);
                Ed25519Signer signer = new Ed25519Signer();
                signer.Init(false, pubKey);
                signer.BlockUpdate(artifact.ToArray(), 0, artifact.Length);
                if (!signer.VerifySignature(signature.ToArray()))
                {
                    throw new SignatureVerificationException("Step 8 (signature): Ed25519 signature verification failed for the artifact.");
                }

                return;
            }
            catch (SignatureVerificationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new SignatureVerificationException("Step 8 (signature): Ed25519 verification error: " + ex.Message, ex);
            }
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
