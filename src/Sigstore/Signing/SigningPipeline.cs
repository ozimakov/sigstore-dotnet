using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using BundleProto = Dev.Sigstore.Bundle.V1.Bundle;
using Dev.Sigstore.Bundle.V1;
using Dev.Sigstore.Common.V1;
using Dev.Sigstore.Rekor.V1;
using Dev.Sigstore.Trustroot.V1;
using Google.Protobuf;
using Io.Intoto;
using Microsoft.Extensions.Logging;
using Sigstore.Crypto;
using Sigstore.Exceptions;
using Sigstore.Fulcio;
using Sigstore.Oidc;
using Sigstore.Rekor;
using Sigstore.Verification;
using CommonHashAlgorithm = Dev.Sigstore.Common.V1.HashAlgorithm;
using X509CertProto = Dev.Sigstore.Common.V1.X509Certificate;

namespace Sigstore.Signing;

/// <summary>
/// Orchestrates the 10-step Sigstore keyless signing pipeline.
/// </summary>
public sealed class SigningPipeline
{
    private readonly IOidcTokenProvider _tokenProvider;
    private readonly IFulcioClient _fulcioClient;
    private readonly IRekorClient _rekorClient;
    private readonly ICertificateVerifier _certificateVerifier;
    private readonly ILogger<SigningPipeline> _logger;

    /// <summary>Creates a signing pipeline.</summary>
    public SigningPipeline(
        IOidcTokenProvider tokenProvider,
        IFulcioClient fulcioClient,
        IRekorClient rekorClient,
        ICertificateVerifier certificateVerifier,
        ILogger<SigningPipeline> logger)
    {
        ArgumentNullException.ThrowIfNull(tokenProvider);
        ArgumentNullException.ThrowIfNull(fulcioClient);
        ArgumentNullException.ThrowIfNull(rekorClient);
        ArgumentNullException.ThrowIfNull(certificateVerifier);
        ArgumentNullException.ThrowIfNull(logger);
        _tokenProvider = tokenProvider;
        _fulcioClient = fulcioClient;
        _rekorClient = rekorClient;
        _certificateVerifier = certificateVerifier;
        _logger = logger;
    }

    /// <summary>
    /// Runs the signing pipeline end-to-end.
    /// </summary>
    /// <param name="artifact">Raw artifact bytes (or DSSE payload).</param>
    /// <param name="payloadType">null for message_signature; content-type string for DSSE.</param>
    /// <param name="oidcAudience">OIDC audience for the token request.</param>
    /// <param name="trustedRoot">Trusted root to validate Fulcio chain and Rekor SET against.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Signing result containing the bundle JSON and signer identity.</returns>
    public Task<SigningResult> RunAsync(
        byte[] artifact,
        string? payloadType,
        string oidcAudience,
        TrustedRoot trustedRoot,
        CancellationToken cancellationToken)
    {
        return RunAsync(artifact, payloadType, oidcAudience, trustedRoot,
            tsaUrl: null, httpClient: null, cancellationToken);
    }

    /// <summary>
    /// Signs multiple artifacts in a single batch, reusing one OIDC token and
    /// Fulcio certificate. Each artifact gets its own Rekor entry and bundle.
    /// </summary>
    public async Task<IReadOnlyList<SigningResult>> RunBatchAsync(
        byte[][] artifacts,
        string oidcAudience,
        TrustedRoot trustedRoot,
        CancellationToken cancellationToken)
    {
        // Steps 2-5: shared across all artifacts (one token, one key, one cert)
        string token = await _tokenProvider.GetTokenAsync(oidcAudience, cancellationToken).ConfigureAwait(false);
        (string subject, long _) = ParseJwtClaims(token);

        using ECDsa ephemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] csrDer = BuildCsr(ephemeralKey);
        X509Certificate2Collection chain = await _fulcioClient
            .GetSigningCertificateAsync(csrDer, token, cancellationToken).ConfigureAwait(false);
        _certificateVerifier.BuildVerifiedChain(chain[0], trustedRoot);

        SigningResult[] results = new SigningResult[artifacts.Length];
        for (int i = 0; i < artifacts.Length; i++)
        {
            byte[] artifact = artifacts[i];
            byte[] signature = Sign(ephemeralKey, artifact, payloadType: null);
            TransparencyLogEntry tlogEntry = await UploadToRekorAsync(
                artifact, null, signature, chain[0], cancellationToken).ConfigureAwait(false);
            VerifyInclusionPromise(tlogEntry);
            string bundleJson = AssembleBundle(artifact, null, signature, chain, tlogEntry);
            SignerIdentity identity = ExtractSignerIdentity(chain[0], subject);
            results[i] = new SigningResult(bundleJson, identity);
        }

        return results;
    }

    public async Task<SigningResult> RunAsync(
        byte[] artifact,
        string? payloadType,
        string oidcAudience,
        TrustedRoot trustedRoot,
        Uri? tsaUrl,
        HttpClient? httpClient,
        CancellationToken cancellationToken)
    {
        _logger.LogDebug("Starting sign operation. PayloadType={PayloadType}, ArtifactSize={Size}",
            payloadType ?? "message_signature", artifact.Length);

        SigningContext context = new SigningContext
        {
            Artifact = artifact,
            PayloadType = payloadType
        };

        try
        {
            // Step 2: Obtain OIDC token
            string token = await _tokenProvider.GetTokenAsync(oidcAudience, cancellationToken).ConfigureAwait(false);
            _logger.LogDebug("OIDC token obtained from provider: {ProviderType}", _tokenProvider.GetType().Name);
            (string subject, long expiry) = ParseJwtClaims(token);

            // Step 3: Generate ephemeral key
            context.EphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            // Step 4: Build CSR
            byte[] csrDer = BuildCsr(context.EphemeralKey);

            // Step 5: Request Fulcio certificate
            X509Certificate2Collection chain = await _fulcioClient
                .GetSigningCertificateAsync(csrDer, token, cancellationToken).ConfigureAwait(false);
            _certificateVerifier.BuildVerifiedChain(chain[0], trustedRoot);
            _logger.LogDebug("Fulcio certificate received. Subject={Subject}, NotAfter={NotAfter}",
                chain[0].Subject, chain[0].NotAfter);

            // Step 6: Sign artifact
            byte[] signature = Sign(context.EphemeralKey, artifact, payloadType);

            // Step 7: Upload to Rekor
            TransparencyLogEntry tlogEntry = await UploadToRekorAsync(
                artifact, payloadType, signature, chain[0], cancellationToken).ConfigureAwait(false);
            _logger.LogDebug("Rekor entry uploaded. LogIndex={LogIndex}", tlogEntry.LogIndex);

            // Step 8: Validate Rekor SET presence (optional for Rekor v2 which uses TSA timestamps)
            if (tsaUrl is null)
            {
                VerifyInclusionPromise(tlogEntry);
            }

            // Step 9: Request TSA timestamp if configured
            byte[]? tsaTimestamp = null;
            if (tsaUrl is not null && httpClient is not null)
            {
                tsaTimestamp = await RequestTimestampAsync(httpClient, tsaUrl, signature, cancellationToken)
                    .ConfigureAwait(false);
                _logger.LogDebug("TSA timestamp obtained from {TsaUrl}", tsaUrl);
            }

            // Step 10: Assemble bundle
            string bundleJson = AssembleBundle(artifact, payloadType, signature, chain, tlogEntry, tsaTimestamp);
            _logger.LogDebug("Bundle assembled.");

            // Step 10: Extract signer identity and return
            SignerIdentity identity = ExtractSignerIdentity(chain[0], subject);
            return new SigningResult(bundleJson, identity);
        }
        finally
        {
            context.EphemeralKey?.Dispose();
        }
    }

    private static (string subject, long expiry) ParseJwtClaims(string token)
    {
        string[] parts = token.Split('.');
        if (parts.Length != 3)
        {
            throw new OidcTokenException("OIDC token is not a valid JWT (expected three dot-separated parts).");
        }

        string payloadBase64 = parts[1];
        // Pad to 4-byte boundary
        int padding = (4 - payloadBase64.Length % 4) % 4;
        payloadBase64 = payloadBase64.PadRight(payloadBase64.Length + padding, '=');
        payloadBase64 = payloadBase64.Replace('-', '+').Replace('_', '/');

        byte[] payloadBytes;
        try
        {
            payloadBytes = Convert.FromBase64String(payloadBase64);
        }
        catch (FormatException ex)
        {
            throw new OidcTokenException("OIDC token payload is not valid base64url.", ex);
        }

        using JsonDocument doc = JsonDocument.Parse(payloadBytes);
        JsonElement root = doc.RootElement;

        if (!root.TryGetProperty("sub", out JsonElement subEl) || subEl.ValueKind != JsonValueKind.String)
        {
            throw new OidcTokenException("OIDC token is missing the 'sub' claim.");
        }

        string subject = subEl.GetString()!;

        if (!root.TryGetProperty("exp", out JsonElement expEl) || !expEl.TryGetInt64(out long exp))
        {
            throw new OidcTokenException("OIDC token is missing or has an invalid 'exp' claim.");
        }

        long nowUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (exp <= nowUnix)
        {
            throw new OidcTokenException("OIDC token has expired.");
        }

        return (subject, exp);
    }

    private static byte[] BuildCsr(ECDsa ephemeralKey)
    {
        CertificateRequest req = new CertificateRequest(
            "CN=sigstore-dotnet",
            ephemeralKey,
            HashAlgorithmName.SHA256);

        return req.CreateSigningRequest();
    }

    private static byte[] Sign(ECDsa key, byte[] artifact, string? payloadType)
    {
        if (payloadType is null)
        {
            // message_signature: sign SHA-256 digest, DER-encoded per Sigstore spec
            return key.SignData(artifact, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        else
        {
            // DSSE: sign PAE(payloadType, payload), DER-encoded
            byte[] pae = Dsse.PreAuthenticationEncoding(payloadType, artifact);
            return key.SignData(pae, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
    }

    private async Task<TransparencyLogEntry> UploadToRekorAsync(
        byte[] artifact,
        string? payloadType,
        byte[] signature,
        X509Certificate2 leafCert,
        CancellationToken cancellationToken)
    {
        if (payloadType is null)
        {
            byte[] digest = SHA256.HashData(artifact);
            return await _rekorClient.AddHashedRekordEntryAsync(
                digest, signature, leafCert, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            // Build DSSE envelope JSON for Rekor upload
            Envelope envelope = new Envelope
            {
                Payload = ByteString.CopyFrom(artifact),
                PayloadType = payloadType
            };
            envelope.Signatures.Add(new Io.Intoto.Signature { Sig = ByteString.CopyFrom(signature) });

            string envelopeJson = new JsonFormatter(JsonFormatter.Settings.Default).Format(envelope);
            byte[] envelopeBytes = Encoding.UTF8.GetBytes(envelopeJson);

            return await _rekorClient.AddDsseEntryAsync(
                envelopeBytes, leafCert, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Validates that the Rekor response contains a non-empty Signed Entry Timestamp (SET).
    /// During signing we trust the Rekor response (we just made the request over TLS), so
    /// we only verify presence here. Full cryptographic SET verification requires
    /// reconstructing the canonicalized entry payload — this is left for a future version.
    /// </summary>
    private static void VerifyInclusionPromise(TransparencyLogEntry entry)
    {
        if (entry.InclusionPromise is null || entry.InclusionPromise.SignedEntryTimestamp.Length == 0)
        {
            throw new RekorException("Rekor response is missing the inclusion promise (SET).");
        }
    }

    private static async Task<byte[]> RequestTimestampAsync(
        HttpClient httpClient, Uri tsaUrl, byte[] signature, CancellationToken cancellationToken)
    {
        // RFC 3161: timestamp request is the hash of the data to be timestamped
        byte[] hash = SHA256.HashData(signature);

        // Build a minimal RFC 3161 TimeStampReq (DER-encoded ASN.1)
        // We use System.Formats.Asn1 to build the request
        System.Formats.Asn1.AsnWriter writer = new(System.Formats.Asn1.AsnEncodingRules.DER);
        using (writer.PushSequence()) // TimeStampReq
        {
            writer.WriteInteger(1); // version
            using (writer.PushSequence()) // messageImprint
            {
                using (writer.PushSequence()) // hashAlgorithm (AlgorithmIdentifier)
                {
                    writer.WriteObjectIdentifier("2.16.840.1.101.3.4.2.1"); // SHA-256
                }
                writer.WriteOctetString(hash); // hashedMessage
            }
            writer.WriteBoolean(true); // certReq
        }

        byte[] tsReqDer = writer.Encode();

        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, tsaUrl);
        request.Content = new ByteArrayContent(tsReqDer);
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/timestamp-query");

        HttpResponseMessage response = await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            string err = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            throw new SigningException($"TSA returned HTTP {(int)response.StatusCode}: {err}");
        }

        byte[] tsResp = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

        // The response might be a TimeStampResp (wrapping a token) or a raw token.
        // The conformance test expects the raw bytes as-is in the bundle.
        return tsResp;
    }

    private static string AssembleBundle(
        byte[] artifact,
        string? payloadType,
        byte[] signature,
        X509Certificate2Collection chain,
        TransparencyLogEntry tlogEntry,
        byte[]? tsaTimestamp = null)
    {
        // Bundle v0.3: use single `certificate` field (leaf only), not the full chain.
        // The trusted root provides the CA chain for verification.
        VerificationMaterial material = new VerificationMaterial
        {
            Certificate = new X509CertProto { RawBytes = ByteString.CopyFrom(chain[0].RawData) }
        };
        material.TlogEntries.Add(tlogEntry);

        if (tsaTimestamp is not null)
        {
            material.TimestampVerificationData = new TimestampVerificationData();
            material.TimestampVerificationData.Rfc3161Timestamps.Add(
                new Dev.Sigstore.Common.V1.RFC3161SignedTimestamp
                {
                    SignedTimestamp = ByteString.CopyFrom(tsaTimestamp)
                });
        }

        BundleProto bundle = new BundleProto
        {
            MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json",
            VerificationMaterial = material
        };

        if (payloadType is null)
        {
            bundle.MessageSignature = new MessageSignature
            {
                MessageDigest = new HashOutput
                {
                    Algorithm = CommonHashAlgorithm.Sha2256,
                    Digest = ByteString.CopyFrom(SHA256.HashData(artifact))
                },
                Signature = ByteString.CopyFrom(signature)
            };
        }
        else
        {
            Envelope envelope = new Envelope
            {
                Payload = ByteString.CopyFrom(artifact),
                PayloadType = payloadType
            };
            envelope.Signatures.Add(new Io.Intoto.Signature { Sig = ByteString.CopyFrom(signature) });
            bundle.DsseEnvelope = envelope;
        }

        return new JsonFormatter(JsonFormatter.Settings.Default).Format(bundle);
    }

    private static SignerIdentity ExtractSignerIdentity(X509Certificate2 leaf, string jwtSubject)
    {
        string issuer = string.Empty;
        if (X509Extensions.TryGetFulcioStringExtension(leaf, X509Extensions.OidcIssuerOid, out string issuerV2))
        {
            issuer = issuerV2;
        }
        else if (X509Extensions.TryGetFulcioStringExtension(leaf, X509Extensions.OidcIssuerOidLegacy, out string issuerV1))
        {
            issuer = issuerV1;
        }

        X509Extensions.TryGetPrimaryIdentityUri(leaf, out string? sanUri);

        // Prefer the JWT sub claim as the canonical subject (Fulcio copies it into the cert SAN)
        return new SignerIdentity(issuer, jwtSubject, sanUri);
    }
}
