using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Sigstore.Exceptions;
using Sigstore.Fulcio;

namespace Sigstore.Tests.Signing;

public sealed class FulcioClientTests
{
    [Fact]
    public void Ctor_NullHttpClient_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new FulcioClient(null!, new Uri("https://fulcio.example.com")));
    }

    [Fact]
    public void Ctor_NullBaseUrl_Throws()
    {
        using HttpClient http = new();
        Assert.Throws<ArgumentNullException>(() => new FulcioClient(http, null!));
    }

    [Fact]
    public async Task GetSigningCertificateAsync_NullCsr_Throws()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, "");
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            client.GetSigningCertificateAsync(null!, "token", CancellationToken.None));
    }

    [Fact]
    public async Task GetSigningCertificateAsync_NullToken_Throws()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, "");
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, null!, CancellationToken.None));
    }

    [Fact]
    public async Task GetSigningCertificateAsync_Throws_FulcioException_On400()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.BadRequest, "bad request");
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));
        FulcioException ex = await Assert.ThrowsAsync<FulcioException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, "token", CancellationToken.None));
        Assert.Contains("400", ex.Message);
    }

    [Fact]
    public async Task GetSigningCertificateAsync_Throws_FulcioException_On500()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.InternalServerError, "server error");
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));
        FulcioException ex = await Assert.ThrowsAsync<FulcioException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, "token", CancellationToken.None));
        Assert.Contains("500", ex.Message);
    }

    [Fact]
    public async Task GetSigningCertificateAsync_Throws_FulcioException_WhenResponseMissingChainField()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, "{\"unknownField\": {}}");
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));
        await Assert.ThrowsAsync<FulcioException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, "token", CancellationToken.None));
    }

    [Fact]
    public async Task GetSigningCertificateAsync_ParsesPemChain()
    {
        string pem = TwoPemCertificates();
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, pem);
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));

        X509Certificate2Collection chain = await client.GetSigningCertificateAsync(
            new byte[] { 1, 2, 3 }, "token", CancellationToken.None);

        Assert.Equal(2, chain.Count);
        DisposeAll(chain);
    }

    [Fact]
    public async Task GetSigningCertificateAsync_ParsesJsonDetachedSctChain()
    {
        string json = BuildJsonChainWrapper("signedCertificateDetachedSct");
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, json);
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));

        X509Certificate2Collection chain = await client.GetSigningCertificateAsync(
            new byte[] { 1, 2, 3 }, "token", CancellationToken.None);

        Assert.Equal(2, chain.Count);
        DisposeAll(chain);
    }

    [Fact]
    public async Task GetSigningCertificateAsync_ParsesJsonEmbeddedSctChain()
    {
        string json = BuildJsonChainWrapper("signedCertificateEmbeddedSct");
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, json);
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));

        X509Certificate2Collection chain = await client.GetSigningCertificateAsync(
            new byte[] { 1, 2, 3 }, "token", CancellationToken.None);

        Assert.Equal(2, chain.Count);
        DisposeAll(chain);
    }

    [Fact]
    public async Task GetSigningCertificateAsync_EmptyJsonChain_Throws()
    {
        string json = JsonSerializer.Serialize(new
        {
            signedCertificateDetachedSct = new
            {
                chain = new { certificates = Array.Empty<string>() }
            }
        });
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, json);
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));

        await Assert.ThrowsAsync<FulcioException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, "token", CancellationToken.None));
    }

    [Fact]
    public async Task GetSigningCertificateAsync_EmptyCertString_Throws()
    {
        string json = JsonSerializer.Serialize(new
        {
            signedCertificateDetachedSct = new
            {
                chain = new { certificates = new[] { "" } }
            }
        });
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, json);
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));

        await Assert.ThrowsAsync<FulcioException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, "token", CancellationToken.None));
    }

    [Fact]
    public async Task GetSigningCertificateAsync_PemWithoutMarkers_Throws()
    {
        // Body looks like text but contains no certificate markers; PEM parser yields empty collection.
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, "totally not a certificate chain");
        FulcioClient client = new(http, new Uri("https://fulcio.example.com"));

        await Assert.ThrowsAsync<FulcioException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, "token", CancellationToken.None));
    }

    private static HttpClient CreateHttpClient(HttpStatusCode statusCode, string content)
    {
        return new HttpClient(new FakeHttpMessageHandler(statusCode, content));
    }

    private static void DisposeAll(X509Certificate2Collection chain)
    {
        foreach (X509Certificate2 cert in chain)
        {
            cert.Dispose();
        }
    }

    private static string TwoPemCertificates()
    {
        using ECDsa k1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa k2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return ToPem(SelfSign(k1, "CN=test1")) + "\n" + ToPem(SelfSign(k2, "CN=test2"));
    }

    private static string BuildJsonChainWrapper(string topField)
    {
        using ECDsa k1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa k2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string c1 = ToPem(SelfSign(k1, "CN=leaf"));
        string c2 = ToPem(SelfSign(k2, "CN=root"));

        return JsonSerializer.Serialize(new Dictionary<string, object>
        {
            [topField] = new Dictionary<string, object>
            {
                ["chain"] = new Dictionary<string, object>
                {
                    ["certificates"] = new[] { c1, c2 }
                }
            }
        });
    }

    private static X509Certificate2 SelfSign(ECDsa key, string subject)
    {
        CertificateRequest req = new(subject, key, HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static string ToPem(X509Certificate2 cert)
    {
        string b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----";
    }
}
