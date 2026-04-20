using System.Numerics;
using System.Security.Cryptography;
using Sigstore.Exceptions;

namespace Sigstore.Rekor;

/// <summary>
/// RFC 6962 Merkle tree helpers for Rekor-compatible transparency logs.
/// Inclusion proof verification follows the decomposed inner/border walk used by
/// <see href="https://github.com/transparency-dev/merkle">transparency-dev/merkle</see>,
/// which implements the proof semantics described in RFC 6962 (Merkle audit paths).
/// </summary>
public static class MerkleProof
{
    /// <summary>
    /// Verifies that <paramref name="leafHash"/> is included at <paramref name="leafIndex"/> in a tree of
    /// <paramref name="treeSize"/> leaves, yielding <paramref name="rootHash"/> for the supplied
    /// <paramref name="inclusionPath"/>.
    /// </summary>
    /// <param name="leafHash">RFC 6962 leaf hash (32 bytes).</param>
    /// <param name="leafIndex">Zero-based leaf index.</param>
    /// <param name="treeSize">Number of leaves in the tree.</param>
    /// <param name="inclusionPath">Inclusion proof hashes (inner segment then border segment).</param>
    /// <param name="rootHash">Expected tree head (32 bytes).</param>
    /// <exception cref="InclusionProofException">When inputs are malformed or the proof does not verify.</exception>
    public static void VerifyInclusion(
        ReadOnlySpan<byte> leafHash,
        long leafIndex,
        long treeSize,
        IReadOnlyList<byte[]> inclusionPath,
        ReadOnlySpan<byte> rootHash)
    {
        if (leafIndex < 0 || treeSize < 0)
        {
            throw new InclusionProofException("Step 6 (inclusion proof): leaf index and tree size must be non-negative.");
        }

        if (leafIndex >= treeSize)
        {
            throw new InclusionProofException("Step 6 (inclusion proof): leaf index must be smaller than tree size.");
        }

        if (leafHash.Length != 32 || rootHash.Length != 32)
        {
            throw new InclusionProofException("Step 6 (inclusion proof): leaf and root hashes must be 32 bytes (SHA-256).");
        }

        ulong index = (ulong)leafIndex;
        ulong size = (ulong)treeSize;
        DecomposeInclusionProof(index, size, inclusionPath.Count, out int inner, out int border);
        byte[] calculated = RootFromInclusionProof(leafHash.ToArray(), index, size, inclusionPath);
        if (!calculated.AsSpan().SequenceEqual(rootHash))
        {
            throw new InclusionProofException("Step 6 (inclusion proof): computed Merkle root does not match the expected root hash.");
        }
    }

    /// <summary>
    /// Computes the tree head from an inclusion proof (transparency-dev/merkle RootFromInclusionProof).
    /// </summary>
    /// <param name="leafHash">32-byte leaf hash.</param>
    /// <param name="leafIndex">Leaf index.</param>
    /// <param name="treeSize">Tree size.</param>
    /// <param name="proof">Proof elements.</param>
    /// <returns>Computed 32-byte root.</returns>
    public static byte[] RootFromInclusionProof(byte[] leafHash, ulong leafIndex, ulong treeSize, IReadOnlyList<byte[]> proof)
    {
        if (leafIndex >= treeSize)
        {
            throw new InclusionProofException("Step 6 (inclusion proof): index is beyond tree size.");
        }

        if (leafHash.Length != 32)
        {
            throw new InclusionProofException("Step 6 (inclusion proof): leaf hash must be 32 bytes.");
        }

        DecomposeInclusionProof(leafIndex, treeSize, proof.Count, out int inner, out int border);
        byte[][] innerProof = new byte[inner][];
        byte[][] borderProof = new byte[border][];
        for (int i = 0; i < inner; i++)
        {
            innerProof[i] = proof[i];
        }

        for (int i = 0; i < border; i++)
        {
            borderProof[i] = proof[inner + i];
        }

        byte[] res = ChainInner(leafHash, innerProof, leafIndex);
        return ChainBorderRight(res, borderProof);
    }

    /// <summary>
    /// RFC 6962 §2.1 — hash an internal node from child hashes (prefix 0x01).
    /// </summary>
    public static byte[] HashChildren(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != 32 || right.Length != 32)
        {
            throw new InclusionProofException("Step 6 (inclusion proof): child hashes must be 32 bytes.");
        }

        byte[] buffer = new byte[1 + 32 + 32];
        buffer[0] = 0x01;
        left.CopyTo(buffer.AsSpan(1, 32));
        right.CopyTo(buffer.AsSpan(33, 32));
        return SHA256.HashData(buffer);
    }

    /// <summary>
    /// RFC 6962 — leaf hash with domain separation prefix 0x00 over the serialized MerkleTreeLeaf.
    /// </summary>
    public static byte[] HashLeaf(ReadOnlySpan<byte> merkleTreeLeafBytes)
    {
        byte[] buffer = new byte[1 + merkleTreeLeafBytes.Length];
        buffer[0] = 0x00;
        merkleTreeLeafBytes.CopyTo(buffer.AsSpan(1));
        return SHA256.HashData(buffer);
    }

    private static void DecomposeInclusionProof(ulong index, ulong size, int proofLength, out int inner, out int border)
    {
        inner = InnerProofSize(index, size);
        border = BitOperations.PopCount(index >> inner);
        if (proofLength != inner + border)
        {
            throw new InclusionProofException($"Step 6 (inclusion proof): wrong proof size {proofLength}, want {inner + border}.");
        }
    }

    private static int InnerProofSize(ulong index, ulong size)
    {
        return Len64(index ^ (size - 1));
    }

    private static int Len64(ulong value)
    {
        if (value == 0UL)
        {
            return 0;
        }

        return 64 - BitOperations.LeadingZeroCount(value);
    }

    private static byte[] ChainInner(byte[] seed, byte[][] proof, ulong index)
    {
        byte[] current = seed;
        for (int i = 0; i < proof.Length; i++)
        {
            byte[] h = proof[i];
            if (h.Length != 32)
            {
                throw new InclusionProofException("Step 6 (inclusion proof): proof element must be 32 bytes.");
            }

            if (((index >> i) & 1UL) == 0UL)
            {
                current = HashChildren(current, h);
            }
            else
            {
                current = HashChildren(h, current);
            }
        }

        return current;
    }

    private static byte[] ChainBorderRight(byte[] seed, byte[][] proof)
    {
        byte[] current = seed;
        for (int i = 0; i < proof.Length; i++)
        {
            byte[] h = proof[i];
            if (h.Length != 32)
            {
                throw new InclusionProofException("Step 6 (inclusion proof): proof element must be 32 bytes.");
            }

            current = HashChildren(h, current);
        }

        return current;
    }
}
