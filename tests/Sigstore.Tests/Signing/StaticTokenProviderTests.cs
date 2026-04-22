using Sigstore.Oidc;

namespace Sigstore.Tests.Signing;

public sealed class StaticTokenProviderTests
{
    [Fact]
    public void IsAvailable_AlwaysTrue()
    {
        var provider = new StaticTokenProvider("my-token");
        Assert.True(provider.IsAvailable);
    }

    [Fact]
    public async Task GetTokenAsync_ReturnsToken()
    {
        var provider = new StaticTokenProvider("my-token");
        string token = await provider.GetTokenAsync("sigstore", CancellationToken.None);
        Assert.Equal("my-token", token);
    }

    [Fact]
    public async Task GetTokenAsync_IgnoresAudience()
    {
        var provider = new StaticTokenProvider("tok");
        string token = await provider.GetTokenAsync("any-audience", CancellationToken.None);
        Assert.Equal("tok", token);
    }
}
