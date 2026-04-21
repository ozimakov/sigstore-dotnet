using Sigstore.Exceptions;
using Sigstore.Oidc;

namespace Sigstore.Tests.Signing;

public sealed class EnvVarTokenProviderTests
{
    [Fact]
    public void IsAvailable_False_WhenEnvVarAbsent()
    {
        string? prev = Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", null);
            var provider = new EnvVarTokenProvider();
            Assert.False(provider.IsAvailable);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", prev);
        }
    }

    [Fact]
    public void IsAvailable_True_WhenEnvVarSet()
    {
        string? prev = Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", "my-jwt");
            var provider = new EnvVarTokenProvider();
            Assert.True(provider.IsAvailable);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", prev);
        }
    }

    [Fact]
    public async Task GetTokenAsync_ReturnsToken_WhenEnvVarSet()
    {
        string? prev = Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", "test-jwt-value");
            var provider = new EnvVarTokenProvider();
            string token = await provider.GetTokenAsync("sigstore", CancellationToken.None);
            Assert.Equal("test-jwt-value", token);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", prev);
        }
    }

    [Fact]
    public async Task GetTokenAsync_Throws_WhenEnvVarAbsent()
    {
        string? prev = Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", null);
            var provider = new EnvVarTokenProvider();
            await Assert.ThrowsAsync<OidcTokenException>(() =>
                provider.GetTokenAsync("sigstore", CancellationToken.None));
        }
        finally
        {
            Environment.SetEnvironmentVariable("SIGSTORE_ID_TOKEN", prev);
        }
    }
}
