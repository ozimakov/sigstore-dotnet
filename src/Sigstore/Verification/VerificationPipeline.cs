using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using BundleProto = Dev.Sigstore.Bundle.V1.Bundle;
using Dev.Sigstore.Bundle.V1;
using Dev.Sigstore.Common.V1;
using Dev.Sigstore.Rekor.V1;
using Dev.Sigstore.Trustroot.V1;
using Io.Intoto;
using Microsoft.Extensions.Logging;
using Sigstore.Bundle;
using Sigstore.Crypto;
using Sigstore.Exceptions;
using Sigstore.Fulcio;
using Sigstore.Rekor;
using Sigstore.Time;

namespace Sigstore.Verification;

/// <summary>
/// Implements the Sigstore verification stages described in the client specification (bundle verification).
/// </summary>
public sealed class VerificationPipeline
{
    private readonly IBundleParser _bundleParser;
    private readonly ICertificateVerifier _certificateVerifier;
    private readonly ITransparencyLogVerifier _transparencyLogVerifier;
    private readonly ISignatureVerifier _signatureVerifier;
    private readonly ISystemClock _systemClock;
    private readonly ILogger<VerificationPipeline> _logger;

    /// <summary>
    /// Creates a pipeline instance.
    /// </summary>
    public VerificationPipeline(
        IBundleParser bundleParser,
        ICertificateVerifier certificateVerifier,
        ITransparencyLogVerifier transparencyLogVerifier,
        ISignatureVerifier signatureVerifier,
        ISystemClock systemClock,
        ILogger<VerificationPipeline> logger)
    {
        _bundleParser = bundleParser;
        _certificateVerifier = certificateVerifier;
        _transparencyLogVerifier = transparencyLogVerifier;
        _signatureVerifier = signatureVerifier;
        _systemClock = systemClock;
        _logger = logger;
    }

    /// <summary>
    /// Runs verification end-to-end.
    /// </summary>
    /// <param name="bundleJson">Bundle JSON text.</param>
    /// <param name="artifact">Artifact bytes being verified.</param>
    /// <param name="policy">Identity policy.</param>
    /// <param name="trustedRoot">Trusted root material (from TUF or a file).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Structured verification result.</returns>
    public async Task<VerificationResult> RunAsync(
        string bundleJson,
        ReadOnlyMemory<byte> artifact,
        VerificationPolicy policy,
        TrustedRoot trustedRoot,
        CancellationToken cancellationToken)
    {
        List<string> steps = new List<string>();
        await Task.Yield();

        SigstoreBundle bundle = _bundleParser.Parse(bundleJson);
        steps.Add("Step 1: Parsed Sigstore bundle JSON.");

        BundleProto model = bundle.Model;
        X509Certificate2 leaf = ExtractLeafCertificate(model, out List<X509Certificate2> materializedChain);
        _ = materializedChain;

        IReadOnlyList<X509Certificate2> chain = _certificateVerifier.BuildVerifiedChain(leaf, trustedRoot);
        steps.Add("Step 3: Validated Fulcio certificate chain against the trusted root.");

        SignerIdentity identity = ExtractSignerIdentity(leaf);
        EnforceIdentityPolicy(identity, policy);
        steps.Add("Step 4: Identity policy matched issuer and subject material.");

        TransparencyLogEntry tlogEntry = ExtractTransparencyLogEntry(model);
        ValidateCertificateTiming(leaf, tlogEntry, model);
        steps.Add("Step 5: Certificate validity window is consistent with Rekor integrated time and/or RFC 3161 countersignatures.");

        _transparencyLogVerifier.VerifyTransparencyLogEntry(tlogEntry, trustedRoot, steps);

        VerifyArtifactCryptography(model, leaf, artifact);
        steps.Add("Step 8: Verified artifact signature using the leaf certificate public key.");

        _ = _systemClock.UtcNow;
        _logger.LogInformation("Sigstore verification completed successfully.");
        return new VerificationResult(true, identity, chain, tlogEntry, steps);
    }

    private static X509Certificate2 ExtractLeafCertificate(BundleProto model, out List<X509Certificate2> chain)
    {
        chain = new List<X509Certificate2>();
        VerificationMaterial? material = model.VerificationMaterial;
        if (material is null)
        {
            throw new BundleParseException("Step 1 (bundle parse): verification material is missing.");
        }

        if (material.X509CertificateChain is not null && material.X509CertificateChain.Certificates.Count > 0)
        {
            for (int i = 0; i < material.X509CertificateChain.Certificates.Count; i++)
            {
                Dev.Sigstore.Common.V1.X509Certificate c = material.X509CertificateChain.Certificates[i];
#if NET9_0_OR_GREATER
                chain.Add(X509CertificateLoader.LoadCertificate(c.RawBytes.ToByteArray()));
#else
                chain.Add(new X509Certificate2(c.RawBytes.ToByteArray()));
#endif
            }

            return chain[0];
        }

        if (material.Certificate is not null)
        {
#if NET9_0_OR_GREATER
            X509Certificate2 leaf = X509CertificateLoader.LoadCertificate(material.Certificate.RawBytes.ToByteArray());
#else
            X509Certificate2 leaf = new X509Certificate2(material.Certificate.RawBytes.ToByteArray());
#endif
            chain.Add(leaf);
            return leaf;
        }

        throw new BundleParseException("Step 1 (bundle parse): bundle does not contain an X.509 certificate or chain (keyless Fulcio bundles require a certificate).");
    }

    private static SignerIdentity ExtractSignerIdentity(X509Certificate2 leaf)
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

        string subjectMaterial;
        if (X509Extensions.TryGetFulcioStringExtension(leaf, X509Extensions.OidcTokenSubjectOid, out string tokenSubject))
        {
            subjectMaterial = tokenSubject;
        }
        else if (X509Extensions.TryGetPrimaryIdentityUri(leaf, out string uri))
        {
            subjectMaterial = uri;
        }
        else
        {
            subjectMaterial = leaf.Subject;
        }

        X509Extensions.TryGetPrimaryIdentityUri(leaf, out string? sanUri);
        return new SignerIdentity(issuer, subjectMaterial, sanUri);
    }

    private static void EnforceIdentityPolicy(SignerIdentity identity, VerificationPolicy policy)
    {
        if (!string.Equals(identity.OidcIssuer, policy.ExpectedOidcIssuer, StringComparison.Ordinal))
        {
            throw new IdentityPolicyException($"Step 4 (identity policy): OIDC issuer mismatch. Expected '{policy.ExpectedOidcIssuer}' but found '{identity.OidcIssuer}'.");
        }

        switch (policy.CertificateIdentityMatcher)
        {
            case CertificateIdentityMatcher.ExactMatch exact:
                if (!string.Equals(identity.Subject, exact.Expected, StringComparison.Ordinal))
                {
                    throw new IdentityPolicyException($"Step 4 (identity policy): identity mismatch. Expected '{exact.Expected}' but found '{identity.Subject}'.");
                }

                break;
            case CertificateIdentityMatcher.RegexMatch rx:
                if (!rx.Pattern.IsMatch(identity.Subject))
                {
                    throw new IdentityPolicyException($"Step 4 (identity policy): identity '{identity.Subject}' did not match required pattern.");
                }

                break;
            default:
                throw new IdentityPolicyException("Step 4 (identity policy): unsupported identity matcher.");
        }
    }

    private static TransparencyLogEntry ExtractTransparencyLogEntry(BundleProto model)
    {
        VerificationMaterial? material = model.VerificationMaterial;
        if (material is null || material.TlogEntries.Count == 0)
        {
            throw new BundleParseException("Step 1 (bundle parse): transparency log entry is missing from the bundle.");
        }

        return material.TlogEntries[0];
    }

    private static void ValidateCertificateTiming(X509Certificate2 leaf, TransparencyLogEntry entry, BundleProto model)
    {
        DateTimeOffset notBefore = new DateTimeOffset(leaf.NotBefore.ToUniversalTime());
        DateTimeOffset notAfter = new DateTimeOffset(leaf.NotAfter.ToUniversalTime());

        if (entry.IntegratedTime > 0)
        {
            DateTimeOffset integrated = DateTimeOffset.FromUnixTimeSeconds(entry.IntegratedTime).ToUniversalTime();
            if (integrated < notBefore || integrated > notAfter)
            {
                throw new CertificateValidationException("Step 5 (validity window): Rekor integrated time is outside the leaf certificate validity period.");
            }

            return;
        }

        VerificationMaterial? material = model.VerificationMaterial;
        if (material?.TimestampVerificationData is not null)
        {
            for (int i = 0; i < material.TimestampVerificationData.Rfc3161Timestamps.Count; i++)
            {
                RFC3161SignedTimestamp ts = material.TimestampVerificationData.Rfc3161Timestamps[i];
                if (ts.SignedTimestamp.Length == 0)
                {
                    continue;
                }

                if (TryGetPkcs9SigningTime(ts.SignedTimestamp.Span, out DateTimeOffset signingTime))
                {
                    DateTimeOffset t = signingTime.ToUniversalTime();
                    if (t >= notBefore && t <= notAfter)
                    {
                        return;
                    }

                    throw new CertificateValidationException("Step 5 (validity window): RFC 3161 signing time is outside the leaf certificate validity period.");
                }
            }
        }

        // Debug info for timestamp failures
        throw new CertificateValidationException("Step 5 (validity window): neither Rekor integrated time nor verifiable RFC 3161 timestamps were available.");
    }

    private static bool TryGetPkcs9SigningTime(ReadOnlySpan<byte> pkcs7, out DateTimeOffset signingTime)
    {
        signingTime = default;
        try
        {
            // Try RFC 3161 timestamp token (TSTInfo.genTime).
            // The data may be either a raw TimeStampToken (ContentInfo) or a
            // TimeStampResp wrapping it. TryDecode expects the token only.
            byte[] tsBytes = pkcs7.ToArray();
            ReadOnlyMemory<byte> tokenData = new ReadOnlyMemory<byte>(tsBytes);

            if (Rfc3161TimestampToken.TryDecode(tokenData, out Rfc3161TimestampToken? token, out _) && token is not null)
            {
                signingTime = token.TokenInfo.Timestamp;
                return true;
            }

            // If that failed, try unwrapping a TimeStampResp envelope:
            // SEQUENCE { SEQUENCE { INTEGER (status) }, ContentInfo (token) }
            ReadOnlyMemory<byte> unwrapped = TryUnwrapTimestampResponse(tsBytes);
            if (!unwrapped.IsEmpty &&
                Rfc3161TimestampToken.TryDecode(unwrapped, out token, out _) && token is not null)
            {
                signingTime = token.TokenInfo.Timestamp;
                return true;
            }

            // Fall back to PKCS#9 signingTime attribute in CMS
            SignedCms cms = new SignedCms();
            cms.Decode(pkcs7.ToArray());
            if (cms.SignerInfos.Count == 0)
            {
                return false;
            }

            SignerInfo signerInfo = cms.SignerInfos[0];
            foreach (CryptographicAttributeObject attribute in signerInfo.SignedAttributes)
            {
                if (attribute.Oid?.Value != "1.2.840.113549.1.9.5")
                {
                    continue;
                }

                foreach (AsnEncodedData data in attribute.Values)
                {
                    Pkcs9SigningTime st = new Pkcs9SigningTime();
                    st.CopyFrom(data);
                    DateTime dt = st.SigningTime;
                    signingTime = new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc));
                    return true;
                }
            }

            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Unwraps an RFC 3161 TimeStampResp to extract the TimeStampToken (ContentInfo).
    /// TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken ContentInfo OPTIONAL }
    /// </summary>
    private static ReadOnlyMemory<byte> TryUnwrapTimestampResponse(byte[] data)
    {
        try
        {
            AsnReader outer = new AsnReader(data, AsnEncodingRules.DER);
            AsnReader seq = outer.ReadSequence();
            // Skip the status SEQUENCE
            seq.ReadSequence();
            // The remaining data is the TimeStampToken (ContentInfo)
            if (seq.HasData)
            {
                return seq.ReadEncodedValue().ToArray();
            }
        }
        catch (CryptographicException) { }
        catch (AsnContentException) { }

        return ReadOnlyMemory<byte>.Empty;
    }

    private void VerifyArtifactCryptography(BundleProto model, X509Certificate2 leaf, ReadOnlyMemory<byte> artifact)
    {
        switch (model.ContentCase)
        {
            case BundleProto.ContentOneofCase.MessageSignature:
                VerifyHashedMessageSignature(model.MessageSignature, leaf, artifact.Span);
                return;
            case BundleProto.ContentOneofCase.DsseEnvelope:
                VerifyDsseEnvelope(model.DsseEnvelope, leaf, artifact.Span);
                return;
            default:
                throw new BundleParseException("Step 1 (bundle parse): bundle does not contain message_signature or dsse_envelope content.");
        }
    }

    private void VerifyHashedMessageSignature(MessageSignature signature, X509Certificate2 leaf, ReadOnlySpan<byte> artifact)
    {
        if (signature.MessageDigest is null)
        {
            throw new SignatureVerificationException("Step 8 (signature): message_digest is required.");
        }

        HashAlgorithmName hash = MapHashAlgorithm(signature.MessageDigest.Algorithm);
        byte[] digest = ComputeDigest(hash, artifact);
        ReadOnlySpan<byte> expected = signature.MessageDigest.Digest.Span;
        if (!digest.AsSpan().SequenceEqual(expected))
        {
            throw new SignatureVerificationException("Step 8 (signature): artifact digest does not match message_digest in the bundle.");
        }

        ReadOnlySpan<byte> sigBytes = signature.Signature.Span;
        _signatureVerifier.VerifyArtifactSignature(leaf, artifact, sigBytes, hash);
    }

    private void VerifyDsseEnvelope(Envelope envelope, X509Certificate2 leaf, ReadOnlySpan<byte> expectedArtifact)
    {
        if (envelope.Signatures.Count != 1)
        {
            throw new SignatureVerificationException("Step 8 (signature): DSSE envelope must contain exactly one signature.");
        }

        byte[] pae = Dsse.PreAuthenticationEncoding(envelope.PayloadType, envelope.Payload.Span);
        byte[] sig = envelope.Signatures[0].Sig.ToByteArray();
        _signatureVerifier.VerifyArtifactSignature(leaf, pae, sig, HashAlgorithmName.SHA256);

        if (!expectedArtifact.SequenceEqual(envelope.Payload.Span))
        {
            throw new SignatureVerificationException("Step 8 (signature): provided artifact bytes do not match DSSE payload.");
        }
    }

    private static HashAlgorithmName MapHashAlgorithm(Dev.Sigstore.Common.V1.HashAlgorithm algorithm)
    {
        switch ((int)algorithm)
        {
            case 1:
                return HashAlgorithmName.SHA256;
            case 2:
                return HashAlgorithmName.SHA384;
            case 3:
                return HashAlgorithmName.SHA512;
            default:
                throw new SignatureVerificationException("Step 8 (signature): unsupported hash algorithm in message_digest.");
        }
    }

    private static byte[] ComputeDigest(HashAlgorithmName name, ReadOnlySpan<byte> artifact)
    {
        if (name == HashAlgorithmName.SHA256)
        {
            return SHA256.HashData(artifact);
        }

        if (name == HashAlgorithmName.SHA384)
        {
            return SHA384.HashData(artifact);
        }

        if (name == HashAlgorithmName.SHA512)
        {
            return SHA512.HashData(artifact);
        }

        throw new SignatureVerificationException("Step 8 (signature): unsupported digest algorithm.");
    }
}
