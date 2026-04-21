namespace Sigstore.Oidc;

/// <summary>
/// Provides OIDC tokens for Sigstore keyless signing.
/// </summary>
public interface IOidcTokenProvider
{
    /// <summary>
    /// Whether this provider can supply a token in the current environment.
    /// </summary>
    bool IsAvailable { get; }

    /// <summary>
    /// Returns an OIDC token for the specified audience.
    /// </summary>
    /// <param name="audience">OIDC audience (e.g. "sigstore").</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<string> GetTokenAsync(string audience, CancellationToken cancellationToken);
}
