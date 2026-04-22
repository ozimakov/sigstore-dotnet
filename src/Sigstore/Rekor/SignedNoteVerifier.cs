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

        // C2SP spec: signed message is the note body including the trailing newline.
        // separator points to the first \n of the \n\n— separator, so +1 includes the trailing \n.
        // Try with trailing newline first (C2SP spec), then without (some older Rekor checkpoints).
        byte[] messageWithNewline = Encoding.UTF8.GetBytes(noteText.Substring(0, separator + 1));
        byte[] messageWithoutNewline = Encoding.UTF8.GetBytes(noteText.Substring(0, separator));

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
        byte[] signaturePayload = Convert.FromBase64String(signatureBase64);

        // C2SP signed-note format: first 4 bytes are key hint, remaining bytes are the signature.
        if (signaturePayload.Length <= 4)
        {
            throw new TransparencyLogException("Step 6 (transparency log): signed note signature is too short (must include 4-byte key hint + signature).");
        }

        byte[] signatureBytes = signaturePayload.AsSpan(4).ToArray();

        using ECDsa key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(subjectPublicKeyInfoDer, out _);

        // Try both signed region variants (with/without trailing \n) and both signature
        // formats (DER/P1363) for maximum compatibility across Rekor versions.
        bool verified = false;
        foreach (byte[] message in new[] { messageWithNewline, messageWithoutNewline })
        {
            if (key.VerifyData(message, signatureBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence) ||
                key.VerifyData(message, signatureBytes, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                verified = true;
                break;
            }
        }

        if (!verified)
        {
            throw new TransparencyLogException("Step 6 (transparency log): ECDSA signature over signed note text failed verification.");
        }
    }
}
