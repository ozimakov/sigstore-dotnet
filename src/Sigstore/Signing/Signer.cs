using Dev.Sigstore.Trustroot.V1;
using Microsoft.Extensions.Logging;
using Sigstore.Tuf;

namespace Sigstore.Signing;

/// <summary>
/// Primary public entry point for Sigstore keyless signing.
/// </summary>
public sealed class Signer
{
    private readonly SigningPipeline _pipeline;
    private readonly ITufClient _tufClient;
    private readonly string _oidcAudience;
    private readonly ILogger<Signer> _logger;

    /// <summary>
    /// Creates a signer.
    /// </summary>
    /// <param name="pipeline">Signing pipeline.</param>
    /// <param name="tufClient">TUF client used when no explicit trusted root is supplied.</param>
    /// <param name="oidcAudience">OIDC audience string. Defaults to <c>"sigstore"</c> (Public Good Instance).</param>
    /// <param name="logger">Logger.</param>
    public Signer(
        SigningPipeline pipeline,
        ITufClient tufClient,
        string oidcAudience,
        ILogger<Signer> logger)
    {
        ArgumentNullException.ThrowIfNull(pipeline);
        ArgumentNullException.ThrowIfNull(tufClient);
        ArgumentNullException.ThrowIfNull(oidcAudience);
        ArgumentNullException.ThrowIfNull(logger);
        _pipeline = pipeline;
        _tufClient = tufClient;
        _oidcAudience = oidcAudience;
        _logger = logger;
    }

    /// <summary>
    /// Signs raw artifact bytes using the Public Good trusted root fetched via TUF.
    /// Produces a <c>message_signature</c> bundle.
    /// </summary>
    /// <param name="artifact">Artifact bytes to sign.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Signing result containing the bundle JSON and signer identity.</returns>
    public Task<SigningResult> SignAsync(byte[] artifact, CancellationToken cancellationToken)
        => SignAsync(artifact, trustedRootJson: null, cancellationToken);

    /// <summary>
    /// Signs raw artifact bytes using a caller-provided trusted root JSON.
    /// Produces a <c>message_signature</c> bundle.
    /// </summary>
    /// <param name="artifact">Artifact bytes to sign.</param>
    /// <param name="trustedRootJson">Trusted root JSON. When null, the Public Good TUF flow is used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Signing result containing the bundle JSON and signer identity.</returns>
    public async Task<SigningResult> SignAsync(
        byte[] artifact,
        string? trustedRootJson,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        TrustedRoot trustedRoot = await ResolveTrustedRootAsync(trustedRootJson, cancellationToken)
            .ConfigureAwait(false);
        _logger.LogDebug("Starting message_signature sign operation.");
        return await _pipeline.RunAsync(artifact, payloadType: null, _oidcAudience, trustedRoot, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Signs an arbitrary payload within a DSSE envelope using the Public Good trusted root fetched via TUF.
    /// </summary>
    /// <param name="payload">Payload bytes.</param>
    /// <param name="payloadType">Content-type of the payload (e.g. <c>"application/vnd.in-toto+json"</c>).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Signing result containing the bundle JSON and signer identity.</returns>
    public Task<SigningResult> SignDsseAsync(
        byte[] payload,
        string payloadType,
        CancellationToken cancellationToken)
        => SignDsseAsync(payload, payloadType, trustedRootJson: null, cancellationToken);

    /// <summary>
    /// Signs an arbitrary payload within a DSSE envelope using a caller-provided trusted root JSON.
    /// </summary>
    /// <param name="payload">Payload bytes.</param>
    /// <param name="payloadType">Content-type of the payload.</param>
    /// <param name="trustedRootJson">Trusted root JSON. When null, the Public Good TUF flow is used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Signing result containing the bundle JSON and signer identity.</returns>
    public async Task<SigningResult> SignDsseAsync(
        byte[] payload,
        string payloadType,
        string? trustedRootJson,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(payloadType);
        TrustedRoot trustedRoot = await ResolveTrustedRootAsync(trustedRootJson, cancellationToken)
            .ConfigureAwait(false);
        _logger.LogDebug("Starting DSSE sign operation. PayloadType={PayloadType}", payloadType);
        return await _pipeline.RunAsync(payload, payloadType, _oidcAudience, trustedRoot, cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Signs multiple artifacts in a single batch, reusing one OIDC token and
    /// Fulcio certificate across all artifacts. Each artifact gets its own Rekor
    /// entry and bundle. Produces <c>message_signature</c> bundles.
    /// </summary>
    /// <param name="artifacts">Artifact byte arrays to sign.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>One <see cref="SigningResult"/> per artifact, in input order.</returns>
    public async Task<IReadOnlyList<SigningResult>> SignBatchAsync(
        IEnumerable<byte[]> artifacts,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifacts);
        byte[][] items = artifacts.ToArray();
        if (items.Length == 0)
        {
            return Array.Empty<SigningResult>();
        }

        TrustedRoot trustedRoot = await ResolveTrustedRootAsync(null, cancellationToken)
            .ConfigureAwait(false);
        _logger.LogDebug("Starting batch sign operation. Count={Count}", items.Length);
        return await _pipeline.RunBatchAsync(items, _oidcAudience, trustedRoot, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<TrustedRoot> ResolveTrustedRootAsync(string? trustedRootJson, CancellationToken ct)
    {
        if (trustedRootJson is null)
        {
            return await _tufClient.FetchPublicGoodTrustedRootAsync(ct).ConfigureAwait(false);
        }

        return TrustedRootLoader.Parse(trustedRootJson);
    }
}
