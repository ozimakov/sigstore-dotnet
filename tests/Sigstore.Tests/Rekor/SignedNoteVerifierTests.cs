using System.Security.Cryptography;
using System.Text;
using Sigstore.Exceptions;
using Sigstore.Rekor;

namespace Sigstore.Tests.Rekor;

public sealed class SignedNoteVerifierTests
{
    [Fact]
    public void VerifyEcdsaP256Sha256_ValidNote_DoesNotThrow()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spki = key.ExportSubjectPublicKeyInfo();
        byte[] keyHint = SHA256.HashData(spki).AsSpan(0, 4).ToArray();

        // C2SP signed-note format:
        // <body>
        // \n
        // — <name> <base64(keyhint || sig)>
        string body = "test.example.com\n42\nrootHashBase64=\n";
        byte[] signature = key.SignData(Encoding.UTF8.GetBytes(body), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        byte[] payload = new byte[4 + signature.Length];
        keyHint.CopyTo(payload, 0);
        signature.CopyTo(payload, 4);
        string noteText = body + "\n— test.example.com " + Convert.ToBase64String(payload) + "\n";

        SignedNoteVerifier.VerifyEcdsaP256Sha256(noteText, spki);
    }

    [Fact]
    public void VerifyEcdsaP256Sha256_MissingSeparator_Throws()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spki = key.ExportSubjectPublicKeyInfo();
        string noteText = "no separator here";

        Assert.Throws<TransparencyLogException>(() =>
            SignedNoteVerifier.VerifyEcdsaP256Sha256(noteText, spki));
    }

    [Fact]
    public void VerifyEcdsaP256Sha256_TamperedSignature_Throws()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spki = key.ExportSubjectPublicKeyInfo();
        byte[] keyHint = SHA256.HashData(spki).AsSpan(0, 4).ToArray();

        string body = "test.example.com\n42\nrootHashBase64=\n";
        byte[] signature = key.SignData(Encoding.UTF8.GetBytes(body), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        signature[^1] ^= 0xFF; // tamper
        byte[] payload = new byte[4 + signature.Length];
        keyHint.CopyTo(payload, 0);
        signature.CopyTo(payload, 4);
        string noteText = body + "\n— test.example.com " + Convert.ToBase64String(payload) + "\n";

        Assert.Throws<TransparencyLogException>(() =>
            SignedNoteVerifier.VerifyEcdsaP256Sha256(noteText, spki));
    }

    [Fact]
    public void VerifyEcdsaP256Sha256_MultipleSignatures_FindsMatchingHint()
    {
        using ECDsa logKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa cosignerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] logSpki = logKey.ExportSubjectPublicKeyInfo();
        byte[] logHint = SHA256.HashData(logSpki).AsSpan(0, 4).ToArray();
        byte[] cosignerSpki = cosignerKey.ExportSubjectPublicKeyInfo();
        byte[] cosignerHint = SHA256.HashData(cosignerSpki).AsSpan(0, 4).ToArray();

        string body = "test.example.com\n42\nrootHashBase64=\n";

        byte[] logSig = logKey.SignData(Encoding.UTF8.GetBytes(body), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        byte[] logPayload = new byte[4 + logSig.Length];
        logHint.CopyTo(logPayload, 0);
        logSig.CopyTo(logPayload, 4);

        byte[] cosignerSig = cosignerKey.SignData(Encoding.UTF8.GetBytes(body), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        byte[] cosignerPayload = new byte[4 + cosignerSig.Length];
        cosignerHint.CopyTo(cosignerPayload, 0);
        cosignerSig.CopyTo(cosignerPayload, 4);

        // Cosigner signature first, log signature second
        string noteText = body
            + "\n— witness.example " + Convert.ToBase64String(cosignerPayload)
            + "\n— test.example.com " + Convert.ToBase64String(logPayload) + "\n";

        // Should find and verify the log signature even though it's not first
        SignedNoteVerifier.VerifyEcdsaP256Sha256(noteText, logSpki);
    }
}
