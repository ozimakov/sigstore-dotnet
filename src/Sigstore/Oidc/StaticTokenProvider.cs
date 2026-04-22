namespace Sigstore.Oidc;

/// <summary>
/// Wraps a pre-fetched JWT string. Intended for testing and controlled automation
/// only — not for tokens obtained interactively or from untrusted sources.
/// <see cref="IsAvailable"/> always returns <see langword="true"/>; no token validation is performed.
/// </summary>
public sealed class StaticTokenProvider : IOidcTokenProvider
{
    private readonly string _token;

    /// <summary>Creates a provider that returns <paramref name="token"/> on every call.</summary>
    public StaticTokenProvider(string token)
    {
        ArgumentNullException.ThrowIfNull(token);
        _token = token;
    }

    /// <inheritdoc/>
    public bool IsAvailable => true;

    /// <inheritdoc/>
    public Task<string> GetTokenAsync(string audience, CancellationToken cancellationToken)
        => Task.FromResult(_token);
}
