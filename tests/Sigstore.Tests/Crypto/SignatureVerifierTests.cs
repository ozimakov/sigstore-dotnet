using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sigstore.Crypto;
using Sigstore.Exceptions;

namespace Sigstore.Tests.Crypto;

public sealed class SignatureVerifierTests
{
    [Fact]
    public void VerifyArtifactSignature_EcdsaP256_DerEncoded_Succeeds()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 cert = CreateSelfSigned(key);
        byte[] artifact = Encoding.UTF8.GetBytes("artifact bytes");
        byte[] signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        SignatureVerifier verifier = new SignatureVerifier();
        verifier.VerifyArtifactSignature(cert, artifact, signature, HashAlgorithmName.SHA256);
        // Should not throw
    }

    [Fact]
    public void VerifyArtifactSignature_EcdsaP256_IeeeP1363_Succeeds()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 cert = CreateSelfSigned(key);
        byte[] artifact = Encoding.UTF8.GetBytes("artifact bytes");
        byte[] signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        SignatureVerifier verifier = new SignatureVerifier();
        verifier.VerifyArtifactSignature(cert, artifact, signature, HashAlgorithmName.SHA256);
        // Should not throw — verifier accepts both formats
    }

    [Fact]
    public void VerifyArtifactSignature_EcdsaP256_TamperedSignature_Throws()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 cert = CreateSelfSigned(key);
        byte[] artifact = Encoding.UTF8.GetBytes("artifact bytes");
        byte[] signature = key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        signature[^1] ^= 0xFF; // Flip last byte

        SignatureVerifier verifier = new SignatureVerifier();
        Assert.Throws<SignatureVerificationException>(() =>
            verifier.VerifyArtifactSignature(cert, artifact, signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public void VerifyArtifactSignature_Rsa_PssEncoded_Succeeds()
    {
        using RSA key = RSA.Create(2048);
        X509Certificate2 cert = CreateSelfSignedRsa(key);
        byte[] artifact = Encoding.UTF8.GetBytes("artifact bytes");
        byte[] signature = key.SignData(artifact, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        SignatureVerifier verifier = new SignatureVerifier();
        verifier.VerifyArtifactSignature(cert, artifact, signature, HashAlgorithmName.SHA256);
    }

    [Fact]
    public void VerifyArtifactSignature_Rsa_Pkcs1_Succeeds()
    {
        using RSA key = RSA.Create(2048);
        X509Certificate2 cert = CreateSelfSignedRsa(key);
        byte[] artifact = Encoding.UTF8.GetBytes("artifact bytes");
        byte[] signature = key.SignData(artifact, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        SignatureVerifier verifier = new SignatureVerifier();
        verifier.VerifyArtifactSignature(cert, artifact, signature, HashAlgorithmName.SHA256);
    }

    [Fact]
    public void VerifyArtifactSignature_Rsa_TamperedSignature_Throws()
    {
        using RSA key = RSA.Create(2048);
        X509Certificate2 cert = CreateSelfSignedRsa(key);
        byte[] artifact = Encoding.UTF8.GetBytes("artifact bytes");
        byte[] signature = key.SignData(artifact, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        signature[0] ^= 0xFF;

        SignatureVerifier verifier = new SignatureVerifier();
        Assert.Throws<SignatureVerificationException>(() =>
            verifier.VerifyArtifactSignature(cert, artifact, signature, HashAlgorithmName.SHA256));
    }

    [Fact]
    public void VerifyArtifactSignature_WrongArtifact_Throws()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 cert = CreateSelfSigned(key);
        byte[] signedArtifact = Encoding.UTF8.GetBytes("original");
        byte[] differentArtifact = Encoding.UTF8.GetBytes("tampered");
        byte[] signature = key.SignData(signedArtifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        SignatureVerifier verifier = new SignatureVerifier();
        Assert.Throws<SignatureVerificationException>(() =>
            verifier.VerifyArtifactSignature(cert, differentArtifact, signature, HashAlgorithmName.SHA256));
    }

    private static X509Certificate2 CreateSelfSigned(ECDsa key)
    {
        var req = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static X509Certificate2 CreateSelfSignedRsa(RSA key)
    {
        var req = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
