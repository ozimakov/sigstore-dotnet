using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Dev.Sigstore.Common.V1;
using Dev.Sigstore.Rekor.V1;
using Dev.Sigstore.Trustroot.V1;
using Google.Protobuf;
using Microsoft.Extensions.Logging.Abstractions;
using Sigstore.Bundle;
using Sigstore.Fulcio;
using Sigstore.Oidc;
using Sigstore.Rekor;
using Sigstore.Signing;
using Sigstore.Tuf;
using Sigstore.Verification;
using CommonPublicKey = Dev.Sigstore.Common.V1.PublicKey;

namespace Sigstore.Tests.Signing;

/// <summary>
/// End-to-end sign + verify tests using mock Fulcio and Rekor with
/// a test CA and a test Rekor key pair.
/// </summary>
public sealed class SignVerifyRoundTripTests
{
    [Fact]
    public async Task MessageSignature_RoundTrip_Passes()
    {
        RoundTripFixture fixture = new RoundTripFixture();

        Signer signer = fixture.BuildSigner();
        Verifier verifier = fixture.BuildVerifier();

        byte[] artifact = Encoding.UTF8.GetBytes("round-trip test artifact");
        SigningResult signing = await signer.SignAsync(artifact, fixture.TrustedRootJson, CancellationToken.None);

        VerificationPolicy policy = VerificationPolicy.ForExact(
            issuer: "https://accounts.example.com",
            identity: RoundTripFixture.Subject);

        VerificationResult verification = await verifier.VerifyAsync(
            signing.BundleJson,
            artifact,
            policy,
            trustedRootJson: fixture.TrustedRootJson,
            CancellationToken.None);

        Assert.True(verification.IsSuccess);
        Assert.Equal(RoundTripFixture.Subject, verification.SignerIdentity.Subject);
    }

    [Fact]
    public async Task DsseEnvelope_RoundTrip_Passes()
    {
        RoundTripFixture fixture = new RoundTripFixture();

        Signer signer = fixture.BuildSigner();
        Verifier verifier = fixture.BuildVerifier();

        byte[] payload = Encoding.UTF8.GetBytes("{\"_type\":\"https://in-toto.io/Statement/v0.1\"}");
        const string payloadType = "application/vnd.in-toto+json";

        SigningResult signing = await signer.SignDsseAsync(
            payload, payloadType, fixture.TrustedRootJson, CancellationToken.None);

        VerificationPolicy policy = VerificationPolicy.ForExact(
            issuer: "https://accounts.example.com",
            identity: RoundTripFixture.Subject);

        VerificationResult verification = await verifier.VerifyAsync(
            signing.BundleJson,
            payload,
            policy,
            trustedRootJson: fixture.TrustedRootJson,
            CancellationToken.None);

        Assert.True(verification.IsSuccess);
        Assert.Equal(RoundTripFixture.Subject, verification.SignerIdentity.Subject);
    }

    // ── fixture ───────────────────────────────────────────────────────────────

    private sealed class RoundTripFixture
    {
        public const string Subject = "signer@test.example.com";
        private const string Issuer = "https://accounts.example.com";

        private readonly ECDsa _caKey;
        private readonly X509Certificate2 _caCert;
        private readonly ECDsa _rekorKey;

        public string TrustedRootJson { get; }

        public RoundTripFixture()
        {
            _caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            _caCert = CreateSelfSignedCa(_caKey);
            _rekorKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            TrustedRootJson = BuildTrustedRootJson(_caCert, _rekorKey);
        }

        public Signer BuildSigner()
        {
            TransparencyLogEntry tlogEntry = BuildFakeTlogEntry(_rekorKey);
            string validJwt = BuildValidJwt(Subject, Issuer);

            SigningPipeline pipeline = new SigningPipeline(
                new StaticTokenProvider(validJwt),
                new CsrIssuingFulcioClient(_caKey, _caCert, Subject, Issuer),
                new SucceedingRekorClient(tlogEntry),
                new CertificateVerifier(),
                NullLogger<SigningPipeline>.Instance);

            return new Signer(
                pipeline,
                new FakeTufClient(),
                "sigstore",
                NullLogger<Signer>.Instance);
        }

        public Verifier BuildVerifier()
        {
            VerificationPipeline pipeline = new VerificationPipeline(
                new BundleParser(),
                new CertificateVerifier(),
                new TransparencyLogVerifier(),
                new Sigstore.Crypto.SignatureVerifier(),
                new Sigstore.Time.DefaultSystemClock(),
                NullLogger<VerificationPipeline>.Instance);

            return new Verifier(pipeline, new FakeTufClient(), NullLogger<Verifier>.Instance);
        }

        private static X509Certificate2 CreateSelfSignedCa(ECDsa key)
        {
            CertificateRequest req = new CertificateRequest("CN=Test Sigstore CA", key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));
        }

        private static byte[] EncodeFulcioUtf8Extension(string value)
        {
            byte[] valueBytes = System.Text.Encoding.UTF8.GetBytes(value);
            byte[] derValue = new byte[valueBytes.Length + 2];
            derValue[0] = 0x0C; // UTF8String tag
            derValue[1] = (byte)valueBytes.Length;
            valueBytes.CopyTo(derValue, 2);
            return derValue;
        }

        private static X509Certificate2 CreateLeafCert(
            ECDsa leafKey, ECDsa signingKey, X509Certificate2 issuer,
            string email, string oidcIssuer)
        {
            CertificateRequest req = new CertificateRequest(
                "CN=sigstore-dotnet", leafKey, HashAlgorithmName.SHA256);

            // SAN: email
            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddEmailAddress(email);
            req.CertificateExtensions.Add(sanBuilder.Build());
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

            // Fulcio OID 1.3.6.1.4.1.57264.1.8 = OIDC issuer (v2)
            req.CertificateExtensions.Add(
                new X509Extension("1.3.6.1.4.1.57264.1.8", EncodeFulcioUtf8Extension(oidcIssuer), false));

            // Fulcio OID 1.3.6.1.4.1.57264.1.24 = OIDC token sub claim
            // Verifier uses this as the primary subject material when present
            req.CertificateExtensions.Add(
                new X509Extension("1.3.6.1.4.1.57264.1.24", EncodeFulcioUtf8Extension(email), false));

            byte[] serial = new byte[8];
            RandomNumberGenerator.Fill(serial);

            return req.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddMinutes(10), serial)
                .CopyWithPrivateKey(leafKey);
        }

        private static string BuildTrustedRootJson(X509Certificate2 caCert, ECDsa rekorKey)
        {
            byte[] spki = rekorKey.ExportSubjectPublicKeyInfo();
            byte[] logIdBytes = SHA256.HashData(spki);

            TrustedRoot root = new TrustedRoot
            {
                MediaType = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"
            };

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

            string noteBody = "rekor.example.com/test\n1\nabcdef\n";
            string signedRegion = noteBody[..^1];
            byte[] sig = rekorKey.SignData(
                System.Text.Encoding.UTF8.GetBytes(signedRegion), HashAlgorithmName.SHA256);
            string noteText = noteBody + "\n— rekor.example.com/test " + Convert.ToBase64String(sig) + "\n";

            return new TransparencyLogEntry
            {
                LogIndex = 42,
                LogId = new LogId { KeyId = ByteString.CopyFrom(logIdBytes) },
                IntegratedTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                KindVersion = new KindVersion { Kind = "hashedrekord", Version = "0.0.1" },
                CanonicalizedBody = ByteString.CopyFrom(System.Text.Encoding.UTF8.GetBytes("body")),
                InclusionPromise = new InclusionPromise
                {
                    SignedEntryTimestamp = ByteString.CopyFrom(System.Text.Encoding.UTF8.GetBytes(noteText))
                }
            };
        }

        private static string BuildValidJwt(string subject, string issuer)
        {
            long exp = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
            string header = Base64UrlEncode("""{"alg":"ES256","typ":"JWT"}""");
            string payload = Base64UrlEncode(
                $"{{\"sub\":\"{subject}\",\"iss\":\"{issuer}\",\"exp\":{exp}}}");
            return $"{header}.{payload}.fakesig";
        }

        private static string Base64UrlEncode(string input)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(input);
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }

    private sealed class FakeTufClient : ITufClient
    {
        public Task<TrustedRoot> FetchPublicGoodTrustedRootAsync(CancellationToken ct)
            => throw new InvalidOperationException("TUF not used in round-trip tests.");
    }

    private sealed class SucceedingFulcioClient : IFulcioClient
    {
        private readonly X509Certificate2 _leaf;
        public SucceedingFulcioClient(X509Certificate2 leaf) => _leaf = leaf;
        public Task<X509Certificate2Collection> GetSigningCertificateAsync(
            byte[] csrDer, string idToken, CancellationToken ct)
            => Task.FromResult(new X509Certificate2Collection { _leaf });
    }

    /// <summary>
    /// Fake Fulcio that parses the incoming CSR, extracts the submitted public key,
    /// and issues a leaf certificate signed by the test CA — matching the real Fulcio flow.
    /// </summary>
    private sealed class CsrIssuingFulcioClient : IFulcioClient
    {
        private readonly ECDsa _caKey;
        private readonly X509Certificate2 _caCert;
        private readonly string _email;
        private readonly string _issuer;

        public CsrIssuingFulcioClient(ECDsa caKey, X509Certificate2 caCert, string email, string issuer)
        {
            _caKey = caKey;
            _caCert = caCert;
            _email = email;
            _issuer = issuer;
        }

        public Task<X509Certificate2Collection> GetSigningCertificateAsync(
            byte[] csrDer, string idToken, CancellationToken ct)
        {
            // Load the CSR to get the submitted public key (the pipeline's ephemeral key).
            CertificateRequest leafReq = CertificateRequest.LoadSigningRequest(
                csrDer, HashAlgorithmName.SHA256);

            // SAN: email
            SubjectAlternativeNameBuilder sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddEmailAddress(_email);
            leafReq.CertificateExtensions.Add(sanBuilder.Build());
            leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

            // Fulcio OID 1.3.6.1.4.1.57264.1.8 = OIDC issuer (v2)
            leafReq.CertificateExtensions.Add(
                new X509Extension("1.3.6.1.4.1.57264.1.8", EncodeFulcioUtf8Extension(_issuer), false));

            // Fulcio OID 1.3.6.1.4.1.57264.1.24 = OIDC token sub claim
            leafReq.CertificateExtensions.Add(
                new X509Extension("1.3.6.1.4.1.57264.1.24", EncodeFulcioUtf8Extension(_email), false));

            byte[] serial = new byte[8];
            RandomNumberGenerator.Fill(serial);

            X509Certificate2 leaf = leafReq.Create(
                _caCert,
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddMinutes(10),
                serial);

            return Task.FromResult(new X509Certificate2Collection { leaf });
        }

        private static byte[] EncodeFulcioUtf8Extension(string value)
        {
            byte[] valueBytes = System.Text.Encoding.UTF8.GetBytes(value);
            byte[] derValue = new byte[valueBytes.Length + 2];
            derValue[0] = 0x0C; // UTF8String tag
            derValue[1] = (byte)valueBytes.Length;
            valueBytes.CopyTo(derValue, 2);
            return derValue;
        }
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
}
