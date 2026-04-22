using System.Net;
using System.Security.Cryptography.X509Certificates;
using Sigstore.Exceptions;
using Sigstore.Rekor;

namespace Sigstore.Tests.Signing;

public sealed class RekorClientTests
{
    [Fact]
    public async Task AddHashedRekordEntryAsync_Throws_RekorException_On400()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.BadRequest, "bad request");
        var client = new RekorClient(http, new Uri("https://rekor.example.com"));
        using var cert = CreateSelfSignedCert();
        await Assert.ThrowsAsync<RekorException>(() =>
            client.AddHashedRekordEntryAsync(new byte[32], new byte[64], cert, CancellationToken.None));
    }

    [Fact]
    public async Task AddHashedRekordEntryAsync_Throws_RekorException_On500()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.InternalServerError, "server error");
        var client = new RekorClient(http, new Uri("https://rekor.example.com"));
        using var cert = CreateSelfSignedCert();
        await Assert.ThrowsAsync<RekorException>(() =>
            client.AddHashedRekordEntryAsync(new byte[32], new byte[64], cert, CancellationToken.None));
    }

    [Fact]
    public async Task AddDsseEntryAsync_Throws_RekorException_On400()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.BadRequest, "bad request");
        var client = new RekorClient(http, new Uri("https://rekor.example.com"));
        using var cert = CreateSelfSignedCert();
        await Assert.ThrowsAsync<RekorException>(() =>
            client.AddDsseEntryAsync(new byte[] { 1, 2, 3 }, cert, CancellationToken.None));
    }

    private static HttpClient CreateHttpClient(HttpStatusCode statusCode, string content)
    {
        return new HttpClient(new FakeHttpMessageHandler(statusCode, content));
    }

    private static X509Certificate2 CreateSelfSignedCert()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=test", key, System.Security.Cryptography.HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
