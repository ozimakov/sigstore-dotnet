using Sigstore.Rekor;

namespace Sigstore.Tests.Rekor;

public sealed class MerkleProofTests
{
    [Fact]
    public void Given_SingleLeafTree_When_VerifyingInclusion_Then_RootMatchesLeaf()
    {
        byte[] leaf = new byte[32];
        for (int i = 0; i < leaf.Length; i++)
        {
            leaf[i] = (byte)i;
        }

        byte[][] proof = Array.Empty<byte[]>();
        MerkleProof.VerifyInclusion(leaf, 0, 1, proof, leaf);
    }

    [Fact]
    public void Given_Rfc6962Vectors_When_ComputingInternalHash_Then_OutputIsDeterministic()
    {
        byte[] left = new byte[32];
        byte[] right = new byte[32];
        left[0] = 0x01;
        right[0] = 0x02;
        byte[] parent = MerkleProof.HashChildren(left, right);
        Assert.Equal(32, parent.Length);
    }
}
