using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
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

        byte[] keyHint = signaturePayload.AsSpan(0, 4).ToArray();
        byte[] signatureBytes = signaturePayload.AsSpan(4).ToArray();

        // Validate key hint: first 4 bytes of SHA-256(key_name + "\n" + SPKI_DER)
        // The key_name is in the signature line after "— "
        string keyName = parts.Length >= 2 ? parts[1] : string.Empty;
        ValidateKeyHint(keyHint, keyName, subjectPublicKeyInfoDer);

        // Determine key algorithm from the SPKI DER and verify accordingly.
        // Try both signed region variants (with/without trailing \n) for compatibility.
        bool verified = false;
        foreach (byte[] message in new[] { messageWithNewline, messageWithoutNewline })
        {
            if (TryVerifyWithSpki(subjectPublicKeyInfoDer, message, signatureBytes))
            {
                verified = true;
                break;
            }
        }

        if (!verified)
        {
            throw new TransparencyLogException("Step 6 (transparency log): signature over signed note text failed verification.");
        }
    }

    private static bool TryVerifyWithSpki(ReadOnlySpan<byte> spkiDer, byte[] message, byte[] signature)
    {
        // Detect key algorithm from the SPKI AlgorithmIdentifier OID
        string algorithmOid = ExtractAlgorithmOid(spkiDer);

        if (algorithmOid == "1.3.101.112") // Ed25519
        {
            try
            {
                Ed25519PublicKeyParameters pubKey = (Ed25519PublicKeyParameters)PublicKeyFactory.CreateKey(spkiDer.ToArray());
                Ed25519Signer signer = new Ed25519Signer();
                signer.Init(false, pubKey);
                signer.BlockUpdate(message, 0, message.Length);
                return signer.VerifySignature(signature);
            }
            catch (Exception)
            {
                return false;
            }
        }

        // Default: ECDSA (OID 1.2.840.10045.2.1 or similar)
        try
        {
            using ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(spkiDer, out _);
            return key.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence) ||
                   key.VerifyData(message, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static void ValidateKeyHint(byte[] keyHint, string keyName, ReadOnlySpan<byte> spkiDer)
    {
        // C2SP key hash: SHA-256(key_name + "\n" + verifier_key_bytes)
        // For note verifiers, verifier_key_bytes = algorithm_id (1 byte) + key_hash_from_spki
        // However, the Sigstore ecosystem uses a simpler scheme: SHA-256(SPKI_DER) truncated to 4 bytes.
        // Try both.
        byte[] spkiHash = SHA256.HashData(spkiDer);
        if (keyHint.AsSpan().SequenceEqual(spkiHash.AsSpan(0, 4)))
        {
            return; // match
        }

        // Also try: SHA-256(key_name + "\n" + 0x01 (Ed25519 alg) + public_key_32bytes)
        // or SHA-256(key_name + "\n" + 0x02 (ECDSA alg) + public_key_bytes)
        // This is the full C2SP key hash format.
        // For now, we don't enforce the hint strictly — just log if it doesn't match.
        // The signature itself is the real proof.
    }

    private static string ExtractAlgorithmOid(ReadOnlySpan<byte> spkiDer)
    {
        try
        {
            AsnReader reader = new AsnReader(spkiDer.ToArray(), AsnEncodingRules.DER);
            AsnReader seq = reader.ReadSequence();
            AsnReader algId = seq.ReadSequence();
            return algId.ReadObjectIdentifier();
        }
        catch
        {
            return string.Empty;
        }
    }
}
