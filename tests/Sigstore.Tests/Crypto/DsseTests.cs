using System.Text;
using Sigstore.Crypto;

namespace Sigstore.Tests.Crypto;

public sealed class DsseTests
{
    [Fact]
    public void PreAuthenticationEncoding_ProducesCorrectFormat()
    {
        byte[] payload = Encoding.UTF8.GetBytes("hello");
        byte[] pae = Dsse.PreAuthenticationEncoding("application/json", payload);
        string result = Encoding.UTF8.GetString(pae);

        // DSSEv1 <type_len> <type> <payload_len> <payload>
        Assert.StartsWith("DSSEv1 ", result);
        Assert.Contains("application/json", result);
    }

    [Fact]
    public void PreAuthenticationEncoding_EmptyPayload_Works()
    {
        byte[] pae = Dsse.PreAuthenticationEncoding("text/plain", Array.Empty<byte>());
        string result = Encoding.UTF8.GetString(pae);

        Assert.StartsWith("DSSEv1 ", result);
        Assert.Contains("text/plain", result);
    }

    [Fact]
    public void PreAuthenticationEncoding_DeterministicOutput()
    {
        byte[] payload = Encoding.UTF8.GetBytes("test");
        byte[] pae1 = Dsse.PreAuthenticationEncoding("type/a", payload);
        byte[] pae2 = Dsse.PreAuthenticationEncoding("type/a", payload);

        Assert.Equal(pae1, pae2);
    }
}
