using Sigstore.Oidc;

namespace Sigstore.Tests.Signing;

public sealed class GitHubActionsTokenProviderTests
{
    [Fact]
    public void IsAvailable_False_WhenEnvVarsAbsent()
    {
        string? prevUrl = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");
        string? prevToken = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", null);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
            var provider = new GitHubActionsTokenProvider(new HttpClient());
            Assert.False(provider.IsAvailable);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", prevUrl);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", prevToken);
        }
    }

    [Fact]
    public void IsAvailable_True_WhenRequestUrlPresent()
    {
        string? prevUrl = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL");
        string? prevToken = Environment.GetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        try
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.com/token");
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-token");
            var provider = new GitHubActionsTokenProvider(new HttpClient());
            Assert.True(provider.IsAvailable);
        }
        finally
        {
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_URL", prevUrl);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", prevToken);
        }
    }
}
