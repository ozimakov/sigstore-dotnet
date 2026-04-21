using Sigstore.Exceptions;
using Sigstore.Oidc;

namespace Sigstore.Tests.Signing;

public sealed class AmbientTokenProviderTests
{
    [Fact]
    public void IsAvailable_False_WhenNoEnvVarsSet()
    {
        string? prevUrl = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");
        string? prevToken = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        string? prevSigstore = Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", null);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", null);
            var provider = new AmbientTokenProvider(new HttpClient());
            Assert.False(provider.IsAvailable);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", prevUrl);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", prevToken);
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", prevSigstore);
        }
    }

    [Fact]
    public void IsAvailable_True_WhenSigstoreIdTokenSet()
    {
        string? prevUrl = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");
        string? prevToken = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        string? prevSigstore = Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", "my-jwt");
            var provider = new AmbientTokenProvider(new HttpClient());
            Assert.True(provider.IsAvailable);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", prevUrl);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", prevToken);
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", prevSigstore);
        }
    }

    [Fact]
    public async Task GetTokenAsync_UsesEnvVar_WhenSigstoreIdTokenSet()
    {
        string? prevUrl = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");
        string? prevToken = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        string? prevSigstore = Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", "env-jwt");
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", null);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
            var provider = new AmbientTokenProvider(new HttpClient());
            string token = await provider.GetTokenAsync("sigstore", CancellationToken.None);
            Assert.Equal("env-jwt", token);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", prevUrl);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", prevToken);
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", prevSigstore);
        }
    }

    [Fact]
    public async Task GetTokenAsync_Throws_WhenNoProviderAvailable()
    {
        string? prevUrl = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");
        string? prevToken = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        string? prevSigstore = Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", null);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", null);
            var provider = new AmbientTokenProvider(new HttpClient());
            await Assert.ThrowsAsync<OidcTokenException>(() =>
                provider.GetTokenAsync("sigstore", CancellationToken.None));
        }
        finally
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", prevUrl);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", prevToken);
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", prevSigstore);
        }
    }
}
