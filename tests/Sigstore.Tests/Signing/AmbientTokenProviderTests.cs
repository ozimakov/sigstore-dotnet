using Sigstore.Exceptions;
using Sigstore.Oidc;

namespace Sigstore.Tests.Signing;

public sealed class AmbientTokenProviderTests
{
    [Fact]
    public void IsAvailable_False_WhenNoEnvVarsSet()
    {
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", null);
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
        Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", null);
        var provider = new AmbientTokenProvider(new HttpClient());
        Assert.False(provider.IsAvailable);
    }

    [Fact]
    public void IsAvailable_True_WhenSigstoreIdTokenSet()
    {
        Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", "my-jwt");
        try
        {
            var provider = new AmbientTokenProvider(new HttpClient());
            Assert.True(provider.IsAvailable);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", null);
        }
    }

    [Fact]
    public async Task GetTokenAsync_UsesEnvVar_WhenSigstoreIdTokenSet()
    {
        Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", "env-jwt");
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", null);
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
        try
        {
            var provider = new AmbientTokenProvider(new HttpClient());
            string token = await provider.GetTokenAsync("sigstore", CancellationToken.None);
            Assert.Equal("env-jwt", token);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", null);
        }
    }

    [Fact]
    public async Task GetTokenAsync_Throws_WhenNoProviderAvailable()
    {
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", null);
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
        Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", null);
        var provider = new AmbientTokenProvider(new HttpClient());
        await Assert.ThrowsAsync<OidcTokenException>(() =>
            provider.GetTokenAsync("sigstore", CancellationToken.None));
    }
}
