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
    public async Task<SigningResult> RunAsync(
        byte[] artifact,
        string? payloadType,
        string oidcAudience,
        TrustedRoot trustedRoot,
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
            context.OidcToken = token;

            // Step 3: Generate ephemeral key
            context.EphemeralKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            // Step 4: Build CSR
            byte[] csrDer = BuildCsr(context.EphemeralKey);

            // Step 5: Request Fulcio certificate
            X509Certificate2Collection chain = await _fulcioClient
                .GetSigningCertificateAsync(csrDer, token, cancellationToken).ConfigureAwait(false);
            _certificateVerifier.BuildVerifiedChain(chain[0], trustedRoot);
            context.CertificateChain = chain;
            _logger.LogDebug("Fulcio certificate received. Subject={Subject}, NotAfter={NotAfter}",
                chain[0].Subject, chain[0].NotAfter);

            // Step 6: Sign artifact
            context.Signature = Sign(context.EphemeralKey, artifact, payloadType);

            // Step 7: Upload to Rekor
            TransparencyLogEntry tlogEntry = await UploadToRekorAsync(
                artifact, payloadType, context.Signature, chain[0], cancellationToken).ConfigureAwait(false);
            context.TransparencyLogEntry = tlogEntry;
            _logger.LogDebug("Rekor entry uploaded. LogIndex={LogIndex}", tlogEntry.LogIndex);

            // Step 8: Validate Rekor SET
            VerifyInclusionPromise(tlogEntry, trustedRoot);

            // Step 9: Assemble bundle
            string bundleJson = AssembleBundle(artifact, payloadType, context.Signature, chain, tlogEntry);
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
            // message_signature: sign SHA-256 digest
            return key.SignData(artifact, HashAlgorithmName.SHA256);
        }
        else
        {
            // DSSE: sign PAE(payloadType, payload)
            byte[] pae = Dsse.PreAuthenticationEncoding(payloadType, artifact);
            return key.SignData(pae, HashAlgorithmName.SHA256);
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

    private static void VerifyInclusionPromise(TransparencyLogEntry entry, TrustedRoot trustedRoot)
    {
        if (entry.InclusionPromise is null || entry.InclusionPromise.SignedEntryTimestamp.Length == 0)
        {
            throw new RekorException("Rekor response is missing the inclusion promise (SET).");
        }

        TransparencyLogInstance? logInstance = SelectLogInstance(entry, trustedRoot);
        if (logInstance is null)
        {
            throw new RekorException("No matching trusted transparency log instance found for the Rekor entry.");
        }

        byte[] spki = logInstance.PublicKey.RawBytes.ToByteArray();
        string setText = Encoding.UTF8.GetString(entry.InclusionPromise.SignedEntryTimestamp.ToByteArray());
        setText = setText.Replace("\r\n", "\n", StringComparison.Ordinal);

        try
        {
            SignedNoteVerifier.VerifyEcdsaP256Sha256(setText, spki);
        }
        catch (TransparencyLogException ex)
        {
            throw new RekorException("Rekor inclusion promise (SET) signature is invalid.", ex);
        }
    }

    private static TransparencyLogInstance? SelectLogInstance(TransparencyLogEntry entry, TrustedRoot trustedRoot)
    {
        ReadOnlySpan<byte> wanted = entry.LogId is null ? ReadOnlySpan<byte>.Empty : entry.LogId.KeyId.Span;
        for (int i = 0; i < trustedRoot.Tlogs.Count; i++)
        {
            TransparencyLogInstance candidate = trustedRoot.Tlogs[i];
            ReadOnlySpan<byte> candidateId = candidate.LogId is null ? ReadOnlySpan<byte>.Empty : candidate.LogId.KeyId.Span;
            if (wanted.Length > 0 && candidateId.SequenceEqual(wanted))
            {
                return candidate;
            }
        }

        if (trustedRoot.Tlogs.Count > 0)
        {
            return trustedRoot.Tlogs[0];
        }

        return null;
    }

    private static string AssembleBundle(
        byte[] artifact,
        string? payloadType,
        byte[] signature,
        X509Certificate2Collection chain,
        TransparencyLogEntry tlogEntry)
    {
        X509CertificateChain certChain = new X509CertificateChain();
        for (int i = 0; i < chain.Count; i++)
        {
            certChain.Certificates.Add(new X509CertProto { RawBytes = ByteString.CopyFrom(chain[i].RawData) });
        }

        VerificationMaterial material = new VerificationMaterial
        {
            X509CertificateChain = certChain
        };
        material.TlogEntries.Add(tlogEntry);

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
