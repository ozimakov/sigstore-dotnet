using Sigstore.Signing;
using Sigstore.Verification;

namespace Sigstore.Tests.Signing;

public sealed class SigningResultTests
{
    [Fact]
    public void SigningResult_StoresBundleJsonAndIdentity()
    {
        SignerIdentity identity = new SignerIdentity(
            "https://accounts.example.com",
            "user@example.com",
            null);

        SigningResult result = new SigningResult("{}", identity);

        Assert.Equal("{}", result.BundleJson);
        Assert.Same(identity, result.Identity);
    }

    [Fact]
    public void SigningResult_SupportsValueEquality()
    {
        SignerIdentity identity = new SignerIdentity("https://issuer", "sub", null);

        SigningResult a = new SigningResult("{}", identity);
        SigningResult b = new SigningResult("{}", identity);

        Assert.Equal(a, b);
    }
}
