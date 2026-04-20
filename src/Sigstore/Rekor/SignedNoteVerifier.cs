using System.Security.Cryptography;
using System.Text;
using Sigstore.Exceptions;

namespace Sigstore.Rekor;

/// <summary>
/// Minimal verifier for C2SP-style signed notes used by Rekor checkpoints and signed entry timestamps.
/// See <see href="https://github.com/C2SP/C2SP/blob/main/signed-note.md">signed-note</see>.
/// </summary>
public static class SignedNoteVerifier
{
    /// <summary>
    /// Verifies a signed note using an ECDSA P-256 public key in PKIX SPKI DER form.
    /// </summary>
    /// <param name="noteText">Full note text including signature lines.</param>
    /// <param name="subjectPublicKeyInfoDer">DER-encoded SubjectPublicKeyInfo.</param>
    /// <exception cref="TransparencyLogException">When the signature does not verify.</exception>
    public static void VerifyEcdsaP256Sha256(string noteText, ReadOnlySpan<byte> subjectPublicKeyInfoDer)
    {
        int separator = noteText.LastIndexOf("\n\n— ", StringComparison.Ordinal);
        if (separator < 0)
        {
            throw new TransparencyLogException("Step 6 (transparency log): signed note is missing signature separator.");
        }

        string signedRegion = noteText.Substring(0, separator);
        byte[] message = Encoding.UTF8.GetBytes(signedRegion);

        string[] tailLines = noteText.Substring(separator + 2).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (tailLines.Length == 0)
        {
            throw new TransparencyLogException("Step 6 (transparency log): signed note signature block is empty.");
        }

        string sigLine = tailLines[0].TrimStart();
        if (!sigLine.StartsWith('—'))
        {
            throw new TransparencyLogException("Step 6 (transparency log): signed note signature line is malformed.");
        }

        string[] parts = sigLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
        {
            throw new TransparencyLogException("Step 6 (transparency log): signed note signature line is malformed.");
        }

        string signatureBase64 = parts[^1];
        byte[] signatureBytes = Convert.FromBase64String(signatureBase64);

        using ECDsa key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfoDer, out _);
        if (!key.VerifyData(message, signatureBytes, HashAlgorithmName.SHA256))
        {
            throw new TransparencyLogException("Step 6 (transparency log): ECDSA signature over signed note text failed verification.");
        }
    }
}
