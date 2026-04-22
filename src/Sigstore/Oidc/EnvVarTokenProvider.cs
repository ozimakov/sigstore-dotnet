using Sigstore.Exceptions;

namespace Sigstore.Oidc;

/// <summary>
/// Reads an OIDC token from the <c>SIGSTORE_ID_TOKEN</c> environment variable.
/// </summary>
public sealed class EnvVarTokenProvider : IOidcTokenProvider
{
    /// <inheritdoc/>
    public bool IsAvailable =>
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN"));

    /// <inheritdoc/>
    public Task<string> GetTokenAsync(string audience, CancellationToken cancellationToken)
    {
        string? token = Environment.GetEnvironmentVariable("SIGSTORE_ID_TOKEN");
        if (string.IsNullOrEmpty(token))
        {
            throw new OidcTokenException("SIGSTORE_ID_TOKEN environment variable is not set.");
        }

        return Task.FromResult(token);
    }
}
