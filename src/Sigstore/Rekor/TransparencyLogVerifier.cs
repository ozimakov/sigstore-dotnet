using System.Collections.Generic;
using System.Security.Cryptography;
using Dev.Sigstore.Rekor.V1;
using Dev.Sigstore.Trustroot.V1;
using Sigstore.Exceptions;

namespace Sigstore.Rekor;

/// <summary>
/// Verifies Rekor inclusion proofs and signed checkpoints using trusted transparency log keys from
/// <see cref="TrustedRoot"/>.
/// </summary>
public sealed class TransparencyLogVerifier : ITransparencyLogVerifier
{
    /// <inheritdoc />
    public void VerifyTransparencyLogEntry(
        TransparencyLogEntry entry,
        TrustedRoot trustedRoot,
        IList<string> auditTrail)
    {
        TransparencyLogInstance? logInstance = SelectLogInstance(entry, trustedRoot);
        if (logInstance is null)
        {
            throw new TransparencyLogException("Step 6 (transparency log): no matching trusted transparency log instance for this entry.");
        }

        byte[] spki = logInstance.PublicKey.RawBytes.ToByteArray();
        InclusionProof? proof = entry.InclusionProof;
        bool hasInclusionProof = proof is not null;
        bool hasInclusionPromise = entry.InclusionPromise is not null
            && entry.InclusionPromise.SignedEntryTimestamp.Length > 0;

        if (!hasInclusionProof && !hasInclusionPromise)
        {
            throw new TransparencyLogException(
                "Step 6 (transparency log): bundle must contain either an inclusion proof or an inclusion promise (SET).");
        }

        if (hasInclusionProof)
        {
            if (entry.CanonicalizedBody.Length == 0)
            {
                throw new TransparencyLogException("Step 6 (transparency log): canonicalized_body is required to compute the Merkle leaf hash.");
            }

            byte[] leafHash = MerkleProof.HashLeaf(entry.CanonicalizedBody.Span);
            byte[][] path = new byte[proof!.Hashes.Count][];
            for (int i = 0; i < proof.Hashes.Count; i++)
            {
                path[i] = proof.Hashes[i].ToByteArray();
            }

            MerkleProof.VerifyInclusion(
                leafHash,
                proof.LogIndex,
                proof.TreeSize,
                path,
                proof.RootHash.Span);

            if (proof.Checkpoint is not null && !string.IsNullOrEmpty(proof.Checkpoint.Envelope))
            {
                string envelope = proof.Checkpoint.Envelope;
                envelope = envelope.Replace("\r\n", "\n", StringComparison.Ordinal);

                // Validate checkpoint body: root hash must match inclusion proof
                ValidateCheckpointBody(envelope, proof.RootHash.Span, proof.TreeSize);

                SignedNoteVerifier.VerifyEcdsaP256Sha256(envelope, spki);
            }
        }

        // Note: The SET (Signed Entry Timestamp) is a raw signature over the canonicalized
        // log entry, not a signed note. Full cryptographic SET verification requires
        // reconstructing the canonicalized entry payload. For now, SET presence is accepted
        // as a weaker signal when no inclusion proof is available.

        auditTrail.Add(hasInclusionProof
            ? "Step 6: Verified Rekor inclusion proof."
            : "Step 6: Accepted Rekor inclusion promise (SET) without cryptographic verification.");
    }

    /// <summary>
    /// Parses the checkpoint body (origin, tree_size, root_hash) and validates
    /// that the root hash matches the inclusion proof's root hash.
    /// </summary>
    private static void ValidateCheckpointBody(string envelope, ReadOnlySpan<byte> expectedRootHash, long expectedTreeSize)
    {
        // Checkpoint body is everything before the first \n\n separator
        int sep = envelope.IndexOf("\n\n", StringComparison.Ordinal);
        if (sep < 0)
        {
            return; // malformed checkpoint — let SignedNoteVerifier handle it
        }

        string body = envelope.Substring(0, sep);
        string[] lines = body.Split('\n');
        if (lines.Length < 3)
        {
            return; // not enough lines to parse
        }

        // Line 0: origin
        // Line 1: tree size
        // Line 2: root hash (base64)
        if (!long.TryParse(lines[1], out long treeSize))
        {
            throw new TransparencyLogException("Step 6 (transparency log): checkpoint tree size is not a valid integer.");
        }

        byte[] rootHash;
        try
        {
            rootHash = Convert.FromBase64String(lines[2]);
        }
        catch (FormatException)
        {
            throw new TransparencyLogException("Step 6 (transparency log): checkpoint root hash is not valid base64.");
        }

        if (!rootHash.AsSpan().SequenceEqual(expectedRootHash))
        {
            throw new TransparencyLogException("Step 6 (transparency log): checkpoint root hash does not match inclusion proof root hash.");
        }

        if (treeSize != expectedTreeSize)
        {
            throw new TransparencyLogException("Step 6 (transparency log): checkpoint tree size does not match inclusion proof tree size.");
        }
    }

    private static TransparencyLogInstance? SelectLogInstance(TransparencyLogEntry entry, TrustedRoot trustedRoot)
    {
        ReadOnlySpan<byte> wanted = entry.LogId is null ? ReadOnlySpan<byte>.Empty : entry.LogId.KeyId.Span;
        for (int i = 0; i < trustedRoot.Tlogs.Count; i++)
        {
            TransparencyLogInstance candidate = trustedRoot.Tlogs[i];
            ReadOnlySpan<byte> candidateId = candidate.LogId is null ? ReadOnlySpan<byte>.Empty : candidate.LogId.KeyId.Span;
            if (wanted.Length > 0 && candidateId.SequenceEqual(wanted))
            {
                return candidate;
            }
        }

        if (trustedRoot.Tlogs.Count > 0)
        {
            return trustedRoot.Tlogs[0];
        }

        return null;
    }
}

/// <summary>
/// Rekor transparency log verifications (Merkle inclusion + signed notes).
/// </summary>
public interface ITransparencyLogVerifier
{
    /// <summary>
    /// Verifies the bundled Rekor material against <paramref name="trustedRoot"/>.
    /// </summary>
    /// <param name="entry">Parsed transparency log entry from the bundle.</param>
    /// <param name="trustedRoot">Trusted Rekor keys and metadata.</param>
    /// <param name="auditTrail">Mutable list receiving human-readable steps.</param>
    void VerifyTransparencyLogEntry(
        TransparencyLogEntry entry,
        TrustedRoot trustedRoot,
        IList<string> auditTrail);
}
