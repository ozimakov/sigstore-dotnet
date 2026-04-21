using System.Net.Http;
using Sigstore.Exceptions;

namespace Sigstore.Oidc;

/// <summary>
/// Ordered chain of ambient OIDC token providers: GitHub Actions → <c>SIGSTORE_ID_TOKEN</c> env var.
/// Throws <see cref="OidcTokenException"/> if no provider is available.
/// </summary>
public sealed class AmbientTokenProvider : IOidcTokenProvider
{
    private readonly IOidcTokenProvider[] _providers;

    /// <summary>Creates an ambient provider chain.</summary>
    public AmbientTokenProvider(HttpClient httpClient)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _providers =
        [
            new GitHubActionsTokenProvider(httpClient),
            new EnvVarTokenProvider(),
        ];
    }

    /// <inheritdoc/>
    public bool IsAvailable => Array.Exists(_providers, p => p.IsAvailable);

    /// <inheritdoc/>
    public async Task<string> GetTokenAsync(string audience, CancellationToken cancellationToken)
    {
        foreach (IOidcTokenProvider provider in _providers)
        {
            if (provider.IsAvailable)
            {
                return await provider.GetTokenAsync(audience, cancellationToken).ConfigureAwait(false);
            }
        }

        throw new OidcTokenException(
            "No ambient OIDC token provider is available. " +
            "Set SIGSTORE_ID_TOKEN or run in a GitHub Actions environment with id-token: write permission.");
    }
}
