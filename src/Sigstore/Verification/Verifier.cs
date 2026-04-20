using Dev.Sigstore.Trustroot.V1;
using Microsoft.Extensions.Logging;
using Sigstore.Tuf;

namespace Sigstore.Verification;

/// <summary>
/// Primary public entry point for Sigstore bundle verification.
/// </summary>
public sealed class Verifier
{
    private readonly VerificationPipeline _pipeline;
    private readonly ITufClient _tufClient;
    private readonly ILogger<Verifier> _logger;

    /// <summary>
    /// Creates a verifier.
    /// </summary>
    /// <param name="pipeline">Verification pipeline.</param>
    /// <param name="tufClient">TUF client used when no explicit trusted root is supplied.</param>
    /// <param name="logger">Logger.</param>
    public Verifier(VerificationPipeline pipeline, ITufClient tufClient, ILogger<Verifier> logger)
    {
        _pipeline = pipeline;
        _tufClient = tufClient;
        _logger = logger;
    }

    /// <summary>
    /// Verifies a Sigstore bundle for an artifact using the Public Good trusted root fetched via TUF.
    /// </summary>
    /// <param name="bundleJson">Bundle JSON text.</param>
    /// <param name="artifact">Artifact bytes.</param>
    /// <param name="policy">Identity policy.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Verification result.</returns>
    public Task<VerificationResult> VerifyAsync(
        string bundleJson,
        ReadOnlyMemory<byte> artifact,
        VerificationPolicy policy,
        CancellationToken cancellationToken)
    {
        return VerifyAsync(bundleJson, artifact, policy, trustedRootJson: null, cancellationToken);
    }

    /// <summary>
    /// Verifies a Sigstore bundle, optionally using a caller-provided trusted root JSON (for example from <c>--trusted-root</c> in conformance tests).
    /// </summary>
    /// <param name="bundleJson">Bundle JSON text.</param>
    /// <param name="artifact">Artifact bytes.</param>
    /// <param name="policy">Identity policy.</param>
    /// <param name="trustedRootJson">Optional trusted root JSON. When null, the Public Good TUF flow is used.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Verification result.</returns>
    public async Task<VerificationResult> VerifyAsync(
        string bundleJson,
        ReadOnlyMemory<byte> artifact,
        VerificationPolicy policy,
        string? trustedRootJson,
        CancellationToken cancellationToken)
    {
        TrustedRoot trustedRoot;
        if (trustedRootJson is null)
        {
            trustedRoot = await _tufClient.FetchPublicGoodTrustedRootAsync(cancellationToken).ConfigureAwait(false);
        }
        else
        {
            trustedRoot = TrustedRootLoader.Parse(trustedRootJson);
        }

        _logger.LogInformation("Starting Sigstore verification.");
        return await _pipeline.RunAsync(bundleJson, artifact, policy, trustedRoot, cancellationToken).ConfigureAwait(false);
    }
}
