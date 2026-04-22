using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Sigstore.Exceptions;

namespace Sigstore.Fulcio;

/// <summary>
/// Fulcio CA client using the gRPC-JSON HTTP/1.1 compatible endpoint.
/// </summary>
public sealed class FulcioClient : IFulcioClient
{
    /// <summary>Named HttpClient key used for DI registration.</summary>
    public const string HttpClientName = "Sigstore.Fulcio";

    private readonly HttpClient _httpClient;
    private readonly Uri _baseUrl;

    /// <summary>Creates a Fulcio client.</summary>
    public FulcioClient(HttpClient httpClient, Uri baseUrl)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(baseUrl);
        _httpClient = httpClient;
        _baseUrl = baseUrl;
    }

    /// <inheritdoc/>
    public async Task<X509Certificate2Collection> GetSigningCertificateAsync(
        byte[] csrDer, string idToken, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(csrDer);
        ArgumentNullException.ThrowIfNull(idToken);

        string csrBase64 = Convert.ToBase64String(csrDer);
        string requestJson = JsonSerializer.Serialize(new
        {
            credentials = new { oidcIdentityToken = idToken },
            certificateSigningRequest = new { content = csrBase64 }
        });

        Uri endpoint = new Uri(_baseUrl, "fulcio.v2.CA/CreateSigningCertificate");
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Content = new StringContent(requestJson, Encoding.UTF8, "application/json");

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new FulcioException("Fulcio request failed: " + ex.Message, ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                string truncated = body.Length > 512 ? body[..512] : body;
                throw new FulcioException($"Fulcio returned HTTP {(int)response.StatusCode}: {truncated}");
            }

            string json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return ParseCertificateChain(json);
        }
    }

    private static X509Certificate2Collection ParseCertificateChain(string json)
    {
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;

        JsonElement chain;
        if (root.TryGetProperty("signedCertificateDetachedSct", out JsonElement detached))
        {
            chain = detached.GetProperty("chain");
        }
        else if (root.TryGetProperty("signedCertificateEmbeddedSct", out JsonElement embedded))
        {
            chain = embedded.GetProperty("chain");
        }
        else
        {
            throw new FulcioException("Fulcio response does not contain a recognized certificate chain field.");
        }

        JsonElement certs = chain.GetProperty("certificates");
        X509Certificate2Collection collection = new X509Certificate2Collection();

        foreach (JsonElement certElement in certs.EnumerateArray())
        {
            string? b64 = certElement.GetString();
            if (string.IsNullOrEmpty(b64))
            {
                throw new FulcioException("Fulcio response contains an empty certificate entry.");
            }

            byte[] der = Convert.FromBase64String(b64);
#if NET9_0_OR_GREATER
            collection.Add(X509CertificateLoader.LoadCertificate(der));
#else
            collection.Add(new X509Certificate2(der));
#endif
        }

        if (collection.Count == 0)
        {
            throw new FulcioException("Fulcio response contains an empty certificate chain.");
        }

        return collection;
    }
}
