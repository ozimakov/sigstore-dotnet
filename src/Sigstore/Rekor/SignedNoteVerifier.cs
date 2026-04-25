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

        // Iterate over all signature lines and verify any that match the known key hint.
        // The origin key's signature might not be the first line (cosigners may precede it).
        List<byte[]> knownKeyHints = ComputeKeyHints(subjectPublicKeyInfoDer, tailLines);

        bool foundMatchingLine = false;
        foreach (string rawLine in tailLines)
        {
            string sigLine = rawLine.TrimStart();
            if (!sigLine.StartsWith('\u2014')) // em-dash
            {
                continue;
            }

            string[] parts = sigLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 3)
            {
                continue;
            }

            string signatureBase64 = parts[^1];
            byte[] signaturePayload;
            try
            {
                signaturePayload = Convert.FromBase64String(signatureBase64);
            }
            catch (FormatException)
            {
                continue;
            }

            if (signaturePayload.Length <= 4)
            {
                continue;
            }

            ReadOnlySpan<byte> keyHint = signaturePayload.AsSpan(0, 4);
            byte[] signatureBytes = signaturePayload.AsSpan(4).ToArray();

            // Check if the key hint matches any of our computed hints
            bool hintMatches = false;
            foreach (byte[] hint in knownKeyHints)
            {
                if (keyHint.SequenceEqual(hint.AsSpan(0, 4)))
                {
                    hintMatches = true;
                    break;
                }
            }

            if (!hintMatches)
            {
                continue; // this signature is from a different key
            }

            foundMatchingLine = true;

            // Verify the signature
            foreach (byte[] message in new[] { messageWithNewline, messageWithoutNewline })
            {
                if (TryVerifyWithSpki(subjectPublicKeyInfoDer, message, signatureBytes))
                {
                    return; // verification succeeded
                }
            }

            throw new TransparencyLogException("Step 6 (transparency log): signature over signed note text failed verification.");
        }

        if (!foundMatchingLine)
        {
            throw new TransparencyLogException("Step 6 (transparency log): no checkpoint signature line matches the transparency log key.");
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

    private static List<byte[]> ComputeKeyHints(ReadOnlySpan<byte> spkiDer, string[] sigLines)
    {
        List<byte[]> hints = new List<byte[]>();

        // Hint scheme 1: SHA-256(SPKI_DER) truncated to 4 bytes
        byte[] spkiHash = SHA256.HashData(spkiDer);
        hints.Add(spkiHash);

        // Hint scheme 2: C2SP note key hash - SHA-256(key_name + "\n" + alg_byte + raw_key)
        // Extract key name from signature lines and raw key from SPKI
        string algorithmOid = ExtractAlgorithmOid(spkiDer);
        byte[]? rawKey = ExtractRawPublicKey(spkiDer, algorithmOid);

        if (rawKey is not null)
        {
            // Find possible key names from signature lines
            foreach (string rawLine in sigLines)
            {
                string sigLine = rawLine.TrimStart();
                if (!sigLine.StartsWith('\u2014'))
                {
                    continue;
                }

                string[] parts = sigLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 3)
                {
                    continue;
                }

                string keyName = parts[1];
                byte algByte = algorithmOid == "1.3.101.112" ? (byte)0x01 : (byte)0x02;

                byte[] input = new byte[Encoding.UTF8.GetByteCount(keyName) + 1 + 1 + rawKey.Length];
                int pos = Encoding.UTF8.GetBytes(keyName, input);
                input[pos++] = (byte)'\n';
                input[pos++] = algByte;
                rawKey.CopyTo(input.AsSpan(pos));

                byte[] c2spHash = SHA256.HashData(input);
                hints.Add(c2spHash);
            }
        }

        return hints;
    }

    private static byte[]? ExtractRawPublicKey(ReadOnlySpan<byte> spkiDer, string algorithmOid)
    {
        try
        {
            if (algorithmOid == "1.3.101.112" && spkiDer.Length == 44)
            {
                // Ed25519 SPKI: 12-byte header + 32-byte key
                return spkiDer.Slice(12).ToArray();
            }

            if (algorithmOid == "1.2.840.10045.2.1")
            {
                // ECDSA: parse the BIT STRING to get the raw public key
                AsnReader reader = new AsnReader(spkiDer.ToArray(), AsnEncodingRules.DER);
                AsnReader seq = reader.ReadSequence();
                seq.ReadSequence(); // skip algorithm identifier
                byte[] bits = seq.ReadBitString(out _);
                // Hash the raw key for the C2SP scheme
                return SHA256.HashData(bits);
            }
        }
        catch
        {
            // ignore
        }

        return null;
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
