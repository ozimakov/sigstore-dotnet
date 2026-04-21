using System.Net;
using System.Security.Cryptography.X509Certificates;
using Sigstore.Exceptions;
using Sigstore.Fulcio;

namespace Sigstore.Tests.Signing;

public sealed class FulcioClientTests
{
    [Fact]
    public async Task GetSigningCertificateAsync_Throws_FulcioException_On400()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.BadRequest, "bad request");
        var client = new FulcioClient(http, new Uri("https://fulcio.example.com"));
        await Assert.ThrowsAsync<FulcioException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, "token", CancellationToken.None));
    }

    [Fact]
    public async Task GetSigningCertificateAsync_Throws_FulcioException_On500()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.InternalServerError, "server error");
        var client = new FulcioClient(http, new Uri("https://fulcio.example.com"));
        await Assert.ThrowsAsync<FulcioException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, "token", CancellationToken.None));
    }

    [Fact]
    public async Task GetSigningCertificateAsync_Throws_FulcioException_WhenResponseMissingChainField()
    {
        using HttpClient http = CreateHttpClient(HttpStatusCode.OK, "{\"unknownField\": {}}");
        var client = new FulcioClient(http, new Uri("https://fulcio.example.com"));
        await Assert.ThrowsAsync<FulcioException>(() =>
            client.GetSigningCertificateAsync(new byte[] { 1, 2, 3 }, "token", CancellationToken.None));
    }

    private static HttpClient CreateHttpClient(HttpStatusCode statusCode, string content)
    {
        return new HttpClient(new FakeMessageHandler(statusCode, content));
    }

    private sealed class FakeMessageHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly string _content;

        public FakeMessageHandler(HttpStatusCode statusCode, string content)
        {
            _statusCode = statusCode;
            _content = content;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(_statusCode)
            {
                Content = new StringContent(_content)
            });
        }
    }
}
