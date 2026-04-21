using Sigstore.Oidc;

namespace Sigstore.Tests.Signing;

public sealed class GitHubActionsTokenProviderTests
{
    [Fact]
    public void IsAvailable_False_WhenEnvVarsAbsent()
    {
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", null);
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
        var provider = new GitHubActionsTokenProvider(new HttpClient());
        Assert.False(provider.IsAvailable);
    }

    [Fact]
    public void IsAvailable_True_WhenRequestUrlPresent()
    {
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token");
        Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-token");
        try
        {
            var provider = new GitHubActionsTokenProvider(new HttpClient());
            Assert.True(provider.IsAvailable);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", null);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
        }
    }
}
