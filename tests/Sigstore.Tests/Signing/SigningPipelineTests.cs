using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Dev.Sigstore.Common.V1;
using Dev.Sigstore.Rekor.V1;
using Dev.Sigstore.Trustroot.V1;
using CommonPublicKey = Dev.Sigstore.Common.V1.PublicKey;
using Google.Protobuf;
using Microsoft.Extensions.Logging.Abstractions;
using Sigstore.Exceptions;
using Sigstore.Fulcio;
using Sigstore.Oidc;
using Sigstore.Rekor;
using Sigstore.Signing;
using Sigstore.Verification;

namespace Sigstore.Tests.Signing;

public sealed class SigningPipelineTests
{
    // ── happy path: message_signature ────────────────────────────────────────

    [Fact]
    public async Task RunAsync_MessageSignature_ReturnsBundleAndIdentity()
    {
        using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 caCert = CreateSelfSignedCa(caKey);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 leafCert = CreateLeafCert(leafKey, caKey, caCert, "test@example.com");
        using ECDsa rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        TrustedRoot trustedRoot = BuildTrustedRoot(caCert, rekorKey);
        TransparencyLogEntry tlogEntry = BuildFakeTlogEntry(rekorKey);

        SigningPipeline pipeline = BuildPipeline(
            leafCert,
            leafKey,
            tlogEntry);

        byte[] artifact = Encoding.UTF8.GetBytes("hello world");
        SigningResult result = await pipeline.RunAsync(
            artifact, payloadType: null, "sigstore", trustedRoot, CancellationToken.None);

        Assert.False(string.IsNullOrEmpty(result.BundleJson));
        Assert.Contains("messageSignature", result.BundleJson);
        Assert.NotNull(result.Identity);
    }

    // ── happy path: DSSE ──────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_DsseEnvelope_ReturnsBundleAndIdentity()
    {
        using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 caCert = CreateSelfSignedCa(caKey);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 leafCert = CreateLeafCert(leafKey, caKey, caCert, "test@example.com");
        using ECDsa rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        TrustedRoot trustedRoot = BuildTrustedRoot(caCert, rekorKey);
        TransparencyLogEntry tlogEntry = BuildFakeTlogEntry(rekorKey);

        SigningPipeline pipeline = BuildPipeline(
            leafCert,
            leafKey,
            tlogEntry);

        byte[] payload = Encoding.UTF8.GetBytes("{\"statement\":\"test\"}");
        SigningResult result = await pipeline.RunAsync(
            payload, "application/vnd.in-toto+json", "sigstore", trustedRoot, CancellationToken.None);

        Assert.False(string.IsNullOrEmpty(result.BundleJson));
        Assert.Contains("dsseEnvelope", result.BundleJson);
        Assert.NotNull(result.Identity);
    }

    // ── OIDC token failure ────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_OidcProviderThrows_PropagatesOidcTokenException()
    {
        IOidcTokenProvider failingProvider = new FailingTokenProvider();
        IFulcioClient fulcio = new UnreachableFulcioClient();
        IRekorClient rekor = new UnreachableRekorClient();
        ICertificateVerifier certVerifier = new AcceptAllCertificateVerifier();

        SigningPipeline pipeline = new SigningPipeline(
            failingProvider, fulcio, rekor, certVerifier,
            NullLogger<SigningPipeline>.Instance);

        TrustedRoot emptyRoot = new TrustedRoot();

        await Assert.ThrowsAsync<OidcTokenException>(() =>
            pipeline.RunAsync(new byte[] { 1 }, null, "sigstore", emptyRoot, CancellationToken.None));
    }

    // ── Fulcio failure ────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_FulcioThrows_PropagatesFulcioException()
    {
        IOidcTokenProvider tokenProvider = new StaticTokenProvider(BuildValidJwt("sub@example.com"));
        IFulcioClient failingFulcio = new FailingFulcioClient();
        IRekorClient rekor = new UnreachableRekorClient();
        ICertificateVerifier certVerifier = new AcceptAllCertificateVerifier();

        SigningPipeline pipeline = new SigningPipeline(
            tokenProvider, failingFulcio, rekor, certVerifier,
            NullLogger<SigningPipeline>.Instance);

        TrustedRoot emptyRoot = new TrustedRoot();

        await Assert.ThrowsAsync<FulcioException>(() =>
            pipeline.RunAsync(new byte[] { 1 }, null, "sigstore", emptyRoot, CancellationToken.None));
    }

    // ── Rekor failure ─────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_RekorThrows_PropagatesRekorException()
    {
        using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 caCert = CreateSelfSignedCa(caKey);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 leafCert = CreateLeafCert(leafKey, caKey, caCert, "test@example.com");

        TrustedRoot trustedRoot = BuildTrustedRoot(caCert, caKey);

        IOidcTokenProvider tokenProvider = new StaticTokenProvider(BuildValidJwt("test@example.com"));
        IFulcioClient fulcio = new SucceedingFulcioClient(leafCert);
        IRekorClient failingRekor = new FailingRekorClient();
        ICertificateVerifier certVerifier = new RealCertificateVerifier();

        SigningPipeline pipeline = new SigningPipeline(
            tokenProvider, fulcio, failingRekor, certVerifier,
            NullLogger<SigningPipeline>.Instance);

        await Assert.ThrowsAsync<RekorException>(() =>
            pipeline.RunAsync(new byte[] { 1 }, null, "sigstore", trustedRoot, CancellationToken.None));
    }

    // ── expired JWT ───────────────────────────────────────────────────────────

    [Fact]
    public async Task RunAsync_ExpiredJwt_ThrowsOidcTokenException()
    {
        string expiredJwt = BuildJwt("sub@example.com", DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds());
        IOidcTokenProvider tokenProvider = new StaticTokenProvider(expiredJwt);

        SigningPipeline pipeline = new SigningPipeline(
            tokenProvider,
            new UnreachableFulcioClient(),
            new UnreachableRekorClient(),
            new AcceptAllCertificateVerifier(),
            NullLogger<SigningPipeline>.Instance);

        await Assert.ThrowsAsync<OidcTokenException>(() =>
            pipeline.RunAsync(new byte[] { 1 }, null, "sigstore", new TrustedRoot(), CancellationToken.None));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static SigningPipeline BuildPipeline(
        X509Certificate2 leafCert,
        ECDsa leafKey,
        TransparencyLogEntry tlogEntry)
    {
        string validJwt = BuildValidJwt("test@example.com");

        return new SigningPipeline(
            new StaticTokenProvider(validJwt),
            new SucceedingFulcioClient(leafCert),
            new SucceedingRekorClient(tlogEntry),
            new RealCertificateVerifier(),
            NullLogger<SigningPipeline>.Instance);
    }

    private static string BuildValidJwt(string subject)
        => BuildJwt(subject, DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds());

    private static string BuildJwt(string subject, long exp)
    {
        string header = Base64UrlEncode("""{"alg":"ES256","typ":"JWT"}""");
        string payload = Base64UrlEncode($"{{\"sub\":\"{subject}\",\"iss\":\"https://accounts.example.com\",\"exp\":{exp}}}");
        return $"{header}.{payload}.fakesig";
    }

    private static string Base64UrlEncode(string input)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static X509Certificate2 CreateSelfSignedCa(ECDsa key)
    {
        CertificateRequest req = new CertificateRequest(
            "CN=Test CA", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
    }

    private static X509Certificate2 CreateLeafCert(
        ECDsa leafKey, ECDsa signingKey, X509Certificate2 issuer, string email)
    {
        CertificateRequest req = new CertificateRequest(
            "CN=sigstore-dotnet", leafKey, HashAlgorithmName.SHA256);

        // Add email SAN
        SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddEmailAddress(email);
        req.CertificateExtensions.Add(sanBuilder.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

        byte[] serialBytes = new byte[8];
        RandomNumberGenerator.Fill(serialBytes);

        return req.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(10), serialBytes)
            .CopyWithPrivateKey(leafKey);
    }

    private static TrustedRoot BuildTrustedRoot(X509Certificate2 caCert, ECDsa rekorKey)
    {
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logIdBytes = SHA256.HashData(spki);

        TransparencyLogInstance tlog = new TransparencyLogInstance
        {
            PublicKey = new CommonPublicKey { RawBytes = ByteString.CopyFrom(spki) },
            LogId = new LogId { KeyId = ByteString.CopyFrom(logIdBytes) }
        };

        CertificateAuthority ca = new CertificateAuthority
        {
            CertChain = new X509CertificateChain()
        };
        ca.CertChain.Certificates.Add(new Dev.Sigstore.Common.V1.X509Certificate
        {
            RawBytes = ByteString.CopyFrom(caCert.RawData)
        });

        TrustedRoot root = new TrustedRoot();
        root.Tlogs.Add(tlog);
        root.CertificateAuthorities.Add(ca);
        return root;
    }

    private static TransparencyLogEntry BuildFakeTlogEntry(ECDsa rekorKey)
    {
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logIdBytes = SHA256.HashData(spki);

        byte[] body = Encoding.UTF8.GetBytes("body");
        byte[] leafHash = Sigstore.Rekor.MerkleProof.HashLeaf(body);
        return new TransparencyLogEntry
        {
            LogIndex = 0,
            LogId = new LogId { KeyId = ByteString.CopyFrom(logIdBytes) },
            IntegratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            KindVersion = new KindVersion { Kind = "hashedrekord", Version = "0.0.1" },
            CanonicalizedBody = ByteString.CopyFrom(body),
            InclusionPromise = new InclusionPromise
            {
                SignedEntryTimestamp = ByteString.CopyFrom(new byte[] { 0x01, 0x02, 0x03 })
            },
            InclusionProof = new InclusionProof
            {
                LogIndex = 0,
                TreeSize = 1,
                RootHash = ByteString.CopyFrom(leafHash),
            }
        };
    }

    // ── fake implementations ──────────────────────────────────────────────────

    private sealed class FailingTokenProvider : IOidcTokenProvider
    {
        public bool IsAvailable => true;
        public Task<string> GetTokenAsync(string audience, CancellationToken cancellationToken)
            => throw new OidcTokenException("No token available.");
    }

    private sealed class UnreachableFulcioClient : IFulcioClient
    {
        public Task<X509Certificate2Collection> GetSigningCertificateAsync(
            byte[] csrDer, string idToken, CancellationToken cancellationToken)
            => throw new InvalidOperationException("Should not be called.");
    }

    private sealed class FailingFulcioClient : IFulcioClient
    {
        public Task<X509Certificate2Collection> GetSigningCertificateAsync(
            byte[] csrDer, string idToken, CancellationToken cancellationToken)
            => throw new FulcioException("Fulcio unavailable.");
    }

    private sealed class SucceedingFulcioClient : IFulcioClient
    {
        private readonly X509Certificate2 _leaf;
        public SucceedingFulcioClient(X509Certificate2 leaf) => _leaf = leaf;

        public Task<X509Certificate2Collection> GetSigningCertificateAsync(
            byte[] csrDer, string idToken, CancellationToken cancellationToken)
        {
            X509Certificate2Collection col = new X509Certificate2Collection { _leaf };
            return Task.FromResult(col);
        }
    }

    private sealed class UnreachableRekorClient : IRekorClient
    {
        public Task<TransparencyLogEntry> AddHashedRekordEntryAsync(
            byte[] artifactDigest, byte[] signature, X509Certificate2 leafCert, CancellationToken ct)
            => throw new InvalidOperationException("Should not be called.");
        public Task<TransparencyLogEntry> AddDsseEntryAsync(
            byte[] envelopeJson, X509Certificate2 leafCert, CancellationToken ct)
            => throw new InvalidOperationException("Should not be called.");
    }

    private sealed class FailingRekorClient : IRekorClient
    {
        public Task<TransparencyLogEntry> AddHashedRekordEntryAsync(
            byte[] artifactDigest, byte[] signature, X509Certificate2 leafCert, CancellationToken ct)
            => throw new RekorException("Rekor unavailable.");
        public Task<TransparencyLogEntry> AddDsseEntryAsync(
            byte[] envelopeJson, X509Certificate2 leafCert, CancellationToken ct)
            => throw new RekorException("Rekor unavailable.");
    }

    private sealed class SucceedingRekorClient : IRekorClient
    {
        private readonly TransparencyLogEntry _entry;
        public SucceedingRekorClient(TransparencyLogEntry entry) => _entry = entry;

        public Task<TransparencyLogEntry> AddHashedRekordEntryAsync(
            byte[] artifactDigest, byte[] signature, X509Certificate2 leafCert, CancellationToken ct)
            => Task.FromResult(_entry);
        public Task<TransparencyLogEntry> AddDsseEntryAsync(
            byte[] envelopeJson, X509Certificate2 leafCert, CancellationToken ct)
            => Task.FromResult(_entry);
    }

    private sealed class AcceptAllCertificateVerifier : ICertificateVerifier
    {
        public IReadOnlyList<X509Certificate2> BuildVerifiedChain(
            X509Certificate2 leaf, Dev.Sigstore.Trustroot.V1.TrustedRoot trustedRoot)
            => new[] { leaf };
    }

    private sealed class RealCertificateVerifier : ICertificateVerifier
    {
        private readonly CertificateVerifier _inner = new CertificateVerifier();
        public IReadOnlyList<X509Certificate2> BuildVerifiedChain(
            X509Certificate2 leaf, Dev.Sigstore.Trustroot.V1.TrustedRoot trustedRoot)
            => _inner.BuildVerifiedChain(leaf, trustedRoot);
    }
}
