using System.Collections.Generic;
using System.Text;
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
                SignedNoteVerifier.VerifyEcdsaP256Sha256(envelope, spki);
            }
        }

        if (hasInclusionPromise)
        {
            string setText = Encoding.UTF8.GetString(entry.InclusionPromise!.SignedEntryTimestamp.ToByteArray());
            setText = setText.Replace("\r\n", "\n", StringComparison.Ordinal);
            SignedNoteVerifier.VerifyEcdsaP256Sha256(setText, spki);
        }

        auditTrail.Add("Step 6: Verified Rekor inclusion proof and/or inclusion promise (SET).");
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
