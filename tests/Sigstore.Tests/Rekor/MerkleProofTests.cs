using System.Security.Cryptography;
using Sigstore.Exceptions;
using Sigstore.Rekor;

namespace Sigstore.Tests.Rekor;

public sealed class MerkleProofTests
{
    [Fact]
    public void Given_SingleLeafTree_When_VerifyingInclusion_Then_RootMatchesLeaf()
    {
        byte[] leaf = Hash("a");
        byte[][] proof = Array.Empty<byte[]>();
        MerkleProof.VerifyInclusion(leaf, 0, 1, proof, leaf);
    }

    [Fact]
    public void Given_TwoLeafTree_When_VerifyingInclusionAtIndex0_Then_VerifySucceeds()
    {
        byte[] l0 = Hash("leaf0");
        byte[] l1 = Hash("leaf1");
        byte[] root = MerkleProof.HashChildren(l0, l1);
        MerkleProof.VerifyInclusion(l0, 0, 2, new[] { l1 }, root);
    }

    [Fact]
    public void Given_TwoLeafTree_When_VerifyingInclusionAtIndex1_Then_VerifySucceeds()
    {
        byte[] l0 = Hash("leaf0");
        byte[] l1 = Hash("leaf1");
        byte[] root = MerkleProof.HashChildren(l0, l1);
        MerkleProof.VerifyInclusion(l1, 1, 2, new[] { l0 }, root);
    }

    [Fact]
    public void Given_FourLeafTree_When_VerifyingMiddleLeaf_Then_VerifySucceeds()
    {
        byte[] l0 = Hash("a");
        byte[] l1 = Hash("b");
        byte[] l2 = Hash("c");
        byte[] l3 = Hash("d");
        byte[] left = MerkleProof.HashChildren(l0, l1);
        byte[] right = MerkleProof.HashChildren(l2, l3);
        byte[] root = MerkleProof.HashChildren(left, right);

        MerkleProof.VerifyInclusion(l2, 2, 4, new[] { l3, left }, root);
    }

    [Fact]
    public void Given_MismatchedRoot_When_VerifyingInclusion_Then_Throws()
    {
        byte[] l0 = Hash("a");
        byte[] l1 = Hash("b");
        byte[] wrongRoot = Hash("nope-not-the-root-32-bytes-pad-x");

        InclusionProofException ex = Assert.Throws<InclusionProofException>(() =>
            MerkleProof.VerifyInclusion(l0, 0, 2, new[] { l1 }, wrongRoot));
        Assert.Contains("root hash", ex.Message);
    }

    [Fact]
    public void Given_NegativeLeafIndex_When_VerifyingInclusion_Then_Throws()
    {
        byte[] leaf = Hash("a");
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.VerifyInclusion(leaf, -1, 1, Array.Empty<byte[]>(), leaf));
    }

    [Fact]
    public void Given_NegativeTreeSize_When_VerifyingInclusion_Then_Throws()
    {
        byte[] leaf = Hash("a");
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.VerifyInclusion(leaf, 0, -1, Array.Empty<byte[]>(), leaf));
    }

    [Fact]
    public void Given_LeafIndexEqualsTreeSize_When_VerifyingInclusion_Then_Throws()
    {
        byte[] leaf = Hash("a");
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.VerifyInclusion(leaf, 1, 1, Array.Empty<byte[]>(), leaf));
    }

    [Fact]
    public void Given_WrongLeafHashLength_When_VerifyingInclusion_Then_Throws()
    {
        byte[] shortLeaf = new byte[16];
        byte[] root = new byte[32];
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.VerifyInclusion(shortLeaf, 0, 1, Array.Empty<byte[]>(), root));
    }

    [Fact]
    public void Given_WrongRootHashLength_When_VerifyingInclusion_Then_Throws()
    {
        byte[] leaf = new byte[32];
        byte[] shortRoot = new byte[16];
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.VerifyInclusion(leaf, 0, 1, Array.Empty<byte[]>(), shortRoot));
    }

    [Fact]
    public void Given_WrongProofLength_When_VerifyingInclusion_Then_Throws()
    {
        byte[] l0 = Hash("a");
        byte[] l1 = Hash("b");
        byte[] root = MerkleProof.HashChildren(l0, l1);
        InclusionProofException ex = Assert.Throws<InclusionProofException>(() =>
            MerkleProof.VerifyInclusion(l0, 0, 2, new[] { l1, l1 }, root));
        Assert.Contains("wrong proof size", ex.Message);
    }

    [Fact]
    public void Given_ProofElementWrongSize_When_VerifyingInclusion_Then_Throws()
    {
        byte[] l0 = Hash("a");
        byte[] root = new byte[32];
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.VerifyInclusion(l0, 0, 2, new[] { new byte[16] }, root));
    }

    [Fact]
    public void RootFromInclusionProof_LeafIndexBeyondTreeSize_Throws()
    {
        byte[] leaf = Hash("a");
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.RootFromInclusionProof(leaf, leafIndex: 5, treeSize: 4, Array.Empty<byte[]>()));
    }

    [Fact]
    public void RootFromInclusionProof_WrongLeafLength_Throws()
    {
        byte[] shortLeaf = new byte[10];
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.RootFromInclusionProof(shortLeaf, leafIndex: 0, treeSize: 1, Array.Empty<byte[]>()));
    }

    [Fact]
    public void HashChildren_ProducesRfc6962InternalNodeWithKnownVector()
    {
        // RFC 6962 §2.1 — internal node hash = SHA-256(0x01 || left || right).
        byte[] left = Hash("left");
        byte[] right = Hash("right");
        byte[] expected = SHA256.HashData(Concat(new byte[] { 0x01 }, left, right));

        byte[] actual = MerkleProof.HashChildren(left, right);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void HashChildren_WrongLeftLength_Throws()
    {
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.HashChildren(new byte[16], new byte[32]));
    }

    [Fact]
    public void HashChildren_WrongRightLength_Throws()
    {
        Assert.Throws<InclusionProofException>(() =>
            MerkleProof.HashChildren(new byte[32], new byte[16]));
    }

    [Fact]
    public void HashLeaf_ProducesRfc6962LeafHashWithKnownVector()
    {
        // RFC 6962 §2.1 — leaf hash = SHA-256(0x00 || leaf bytes).
        byte[] payload = new byte[] { 1, 2, 3, 4, 5 };
        byte[] expected = SHA256.HashData(Concat(new byte[] { 0x00 }, payload));

        byte[] actual = MerkleProof.HashLeaf(payload);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void HashLeaf_AcceptsEmptyInput()
    {
        byte[] actual = MerkleProof.HashLeaf(ReadOnlySpan<byte>.Empty);
        Assert.Equal(SHA256.HashData(new byte[] { 0x00 }), actual);
    }

    private static byte[] Hash(string seed) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(seed));

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        for (int i = 0; i < parts.Length; i++)
        {
            total += parts[i].Length;
        }

        byte[] result = new byte[total];
        int offset = 0;
        for (int i = 0; i < parts.Length; i++)
        {
            Buffer.BlockCopy(parts[i], 0, result, offset, parts[i].Length);
            offset += parts[i].Length;
        }

        return result;
    }
}
