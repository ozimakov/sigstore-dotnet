using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Dev.Sigstore.Common.V1;
using Dev.Sigstore.Rekor.V1;
using Dev.Sigstore.Trustroot.V1;
using Google.Protobuf;
using Google.Protobuf.WellKnownTypes;
using Microsoft.Extensions.Logging.Abstractions;
using Sigstore.Exceptions;
using Sigstore.Fulcio;
using Sigstore.Oidc;
using Sigstore.Rekor;
using Sigstore.Signing;
using Sigstore.Tuf;
using Sigstore.Verification;
using CommonPublicKey = Dev.Sigstore.Common.V1.PublicKey;

namespace Sigstore.Tests.Signing;

public sealed class SignerTests
{
    [Fact]
    public async Task SignAsync_WithTrustedRootJson_ReturnsBundle()
    {
        (SigningPipeline pipeline, string trustedRootJson) = BuildPipelineAndRoot();
        Signer signer = new Signer(
            pipeline,
            new FakeTufClient(),
            "sigstore",
            NullLogger<Signer>.Instance);

        byte[] artifact = Encoding.UTF8.GetBytes("hello");
        SigningResult result = await signer.SignAsync(artifact, trustedRootJson, CancellationToken.None);

        Assert.False(string.IsNullOrEmpty(result.BundleJson));
        Assert.Contains("messageSignature", result.BundleJson);
    }

    [Fact]
    public async Task SignDsseAsync_WithTrustedRootJson_ReturnsDsseBundle()
    {
        (SigningPipeline pipeline, string trustedRootJson) = BuildPipelineAndRoot();
        Signer signer = new Signer(
            pipeline,
            new FakeTufClient(),
            "sigstore",
            NullLogger<Signer>.Instance);

        byte[] payload = Encoding.UTF8.GetBytes("{\"key\":\"value\"}");
        SigningResult result = await signer.SignDsseAsync(
            payload, "application/json", trustedRootJson, CancellationToken.None);

        Assert.False(string.IsNullOrEmpty(result.BundleJson));
        Assert.Contains("dsseEnvelope", result.BundleJson);
    }

    [Fact]
    public async Task SignAsync_NullArtifact_Throws()
    {
        Signer signer = new Signer(
            BuildMinimalPipeline(),
            new FakeTufClient(),
            "sigstore",
            NullLogger<Signer>.Instance);

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            signer.SignAsync(null!, CancellationToken.None));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static (SigningPipeline pipeline, string trustedRootJson) BuildPipelineAndRoot()
    {
        using ECDsa caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 caCert = CreateSelfSignedCa(caKey);
        using ECDsa leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 leafCert = CreateLeafCert(leafKey, caKey, caCert, "signer@example.com");
        using ECDsa rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        string trustedRootJson = BuildTrustedRootJson(caCert, rekorKey);
        TransparencyLogEntry tlogEntry = BuildFakeTlogEntry(rekorKey);

        string validJwt = BuildValidJwt("signer@example.com");

        SigningPipeline pipeline = new SigningPipeline(
            new StaticTokenProvider(validJwt),
            new SucceedingFulcioClient(leafCert),
            new SucceedingRekorClient(tlogEntry),
            new CertificateVerifier(),
            NullLogger<SigningPipeline>.Instance);

        return (pipeline, trustedRootJson);
    }

    private static SigningPipeline BuildMinimalPipeline()
    {
        return new SigningPipeline(
            new StaticTokenProvider(BuildValidJwt("x@x.com")),
            new UnreachableFulcioClient(),
            new UnreachableRekorClient(),
            new AcceptAllCertificateVerifier(),
            NullLogger<SigningPipeline>.Instance);
    }

    private static string BuildValidJwt(string subject)
    {
        long exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
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
        CertificateRequest req = new CertificateRequest("CN=Test CA", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
    }

    private static X509Certificate2 CreateLeafCert(
        ECDsa leafKey, ECDsa signingKey, X509Certificate2 issuer, string email)
    {
        CertificateRequest req = new CertificateRequest("CN=sigstore-dotnet", leafKey, HashAlgorithmName.SHA256);
        SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddEmailAddress(email);
        req.CertificateExtensions.Add(sanBuilder.Build());
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        byte[] serial = new byte[8];
        RandomNumberGenerator.Fill(serial);
        return req.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(10), serial)
            .CopyWithPrivateKey(leafKey);
    }

    private static string BuildTrustedRootJson(X509Certificate2 caCert, ECDsa rekorKey)
    {
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logIdBytes = SHA256.HashData(spki);

        TrustedRoot root = new TrustedRoot { MediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1" };
        root.Tlogs.Add(new TransparencyLogInstance
        {
            PublicKey = new CommonPublicKey { RawBytes = ByteString.CopyFrom(spki) },
            LogId = new LogId { KeyId = ByteString.CopyFrom(logIdBytes) }
        });
        CertificateAuthority ca = new CertificateAuthority
        {
            CertChain = new X509CertificateChain()
        };
        ca.CertChain.Certificates.Add(new Dev.Sigstore.Common.V1.X509Certificate
        {
            RawBytes = ByteString.CopyFrom(caCert.RawData)
        });
        root.CertificateAuthorities.Add(ca);
        return new Google.Protobuf.JsonFormatter(Google.Protobuf.JsonFormatter.Settings.Default).Format(root);
    }

    private static TransparencyLogEntry BuildFakeTlogEntry(ECDsa rekorKey)
    {
        byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
        byte[] logIdBytes = SHA256.HashData(spki);

        byte[] body = Encoding.UTF8.GetBytes("body");
        byte[] leafHash = Sigstore.Rekor.MerkleProof.HashLeaf(body);
        long integratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        long logIndex = 0;

        string logIdHex = Convert.ToHexString(logIdBytes).ToLowerInvariant();
        string bodyB64 = Convert.ToBase64String(body);
        string setPayload = "{" +
            "\"body\":\"" + bodyB64 + "\"," +
            "\"integratedTime\":" + integratedTime + "," +
            "\"logID\":\"" + logIdHex + "\"," +
            "\"logIndex\":" + logIndex +
            "}";
        byte[] setSignature = rekorKey.SignData(
            Encoding.UTF8.GetBytes(setPayload), HashAlgorithmName.SHA256);

        return new TransparencyLogEntry
        {
            LogIndex = logIndex,
            LogId = new LogId { KeyId = ByteString.CopyFrom(logIdBytes) },
            IntegratedTime = integratedTime,
            KindVersion = new KindVersion { Kind = "hashedrekord", Version = "0.0.1" },
            CanonicalizedBody = ByteString.CopyFrom(body),
            InclusionPromise = new InclusionPromise
            {
                SignedEntryTimestamp = ByteString.CopyFrom(setSignature)
            },
            InclusionProof = new InclusionProof
            {
                LogIndex = logIndex,
                TreeSize = 1,
                RootHash = ByteString.CopyFrom(leafHash),
            }
        };
    }

    private sealed class FakeTufClient : ITufClient
    {
        public Task<Dev.Sigstore.Trustroot.V1.TrustedRoot> FetchPublicGoodTrustedRootAsync(CancellationToken ct)
            => throw new InvalidOperationException("TUF not expected in these tests.");
    }

    private sealed class UnreachableFulcioClient : IFulcioClient
    {
        public Task<X509Certificate2Collection> GetSigningCertificateAsync(
            byte[] csrDer, string idToken, CancellationToken ct)
            => throw new InvalidOperationException("Not expected.");
    }

    private sealed class UnreachableRekorClient : IRekorClient
    {
        public Task<TransparencyLogEntry> AddHashedRekordEntryAsync(
            byte[] d, byte[] s, X509Certificate2 c, CancellationToken ct)
            => throw new InvalidOperationException("Not expected.");
        public Task<TransparencyLogEntry> AddDsseEntryAsync(
            byte[] e, X509Certificate2 c, CancellationToken ct)
            => throw new InvalidOperationException("Not expected.");
    }

    private sealed class SucceedingFulcioClient : IFulcioClient
    {
        private readonly X509Certificate2 _leaf;
        public SucceedingFulcioClient(X509Certificate2 leaf) => _leaf = leaf;
        public Task<X509Certificate2Collection> GetSigningCertificateAsync(
            byte[] csrDer, string idToken, CancellationToken ct)
            => Task.FromResult(new X509Certificate2Collection { _leaf });
    }

    private sealed class SucceedingRekorClient : IRekorClient
    {
        private readonly TransparencyLogEntry _entry;
        public SucceedingRekorClient(TransparencyLogEntry entry) => _entry = entry;
        public Task<TransparencyLogEntry> AddHashedRekordEntryAsync(
            byte[] d, byte[] s, X509Certificate2 c, CancellationToken ct)
            => Task.FromResult(_entry);
        public Task<TransparencyLogEntry> AddDsseEntryAsync(
            byte[] e, X509Certificate2 c, CancellationToken ct)
            => Task.FromResult(_entry);
    }

    private sealed class AcceptAllCertificateVerifier : ICertificateVerifier
    {
        public IReadOnlyList<X509Certificate2> BuildVerifiedChain(
            X509Certificate2 leaf, Dev.Sigstore.Trustroot.V1.TrustedRoot trustedRoot)
            => new[] { leaf };
    }
}
