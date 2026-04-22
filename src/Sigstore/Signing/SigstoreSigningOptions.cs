using Sigstore.Oidc;

namespace Sigstore.Signing;

/// <summary>
/// Configuration options for <see cref="Signer"/> and the signing pipeline.
/// </summary>
public sealed class SigstoreSigningOptions
{
    /// <summary>
    /// Fulcio CA endpoint URL. Defaults to the Sigstore Public Good Instance.
    /// </summary>
    public Uri FulcioUrl { get; set; } = new Uri("https://fulcio.sigstore.dev/");

    /// <summary>
    /// Rekor transparency log endpoint URL. Defaults to the Sigstore Public Good Instance.
    /// </summary>
    public Uri RekorUrl { get; set; } = new Uri("https://rekor.sigstore.dev/");

    /// <summary>
    /// OIDC audience to request for the signing token. Defaults to <c>"sigstore"</c>.
    /// </summary>
    public string OidcAudience { get; set; } = "sigstore";

    /// <summary>
    /// Override the default <see cref="AmbientTokenProvider"/>.
    /// When <see langword="null"/>, <see cref="AmbientTokenProvider"/> is used (GHA → SIGSTORE_ID_TOKEN).
    /// </summary>
    public IOidcTokenProvider? TokenProvider { get; set; }

    /// <summary>
    /// HTTP client timeout for Fulcio and Rekor calls. Defaults to 30 seconds.
    /// </summary>
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(30);
}
