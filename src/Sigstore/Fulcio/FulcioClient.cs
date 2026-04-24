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

        // Convert DER CSR to PEM for the Fulcio v2 REST API
        string csrPem = "-----BEGIN CERTIFICATE REQUEST-----\n"
            + Convert.ToBase64String(csrDer)
            + "\n-----END CERTIFICATE REQUEST-----\n";
        string csrBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(csrPem));
        string requestJson = JsonSerializer.Serialize(new
        {
            certificateSigningRequest = csrBase64
        });

        Uri endpoint = new Uri(_baseUrl, "api/v2/signingCert");
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Content = new StringContent(requestJson, Encoding.UTF8, "application/json");
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {idToken}");
        request.Headers.TryAddWithoutValidation("Accept", "application/pem-certificate-chain");

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

            string responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            // Try PEM parsing first (we request application/pem-certificate-chain),
            // fall back to JSON if the response isn't PEM.
            if (responseBody.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {
                return ParsePemCertificateChain(responseBody);
            }

            return ParseCertificateChain(responseBody);
        }
    }

    private static X509Certificate2Collection ParseCertificateChain(string json)
    {
        try
        {
            return ParseCertificateChainCore(json);
        }
        catch (FulcioException)
        {
            throw;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or KeyNotFoundException or InvalidOperationException)
        {
            throw new FulcioException("Failed to parse Fulcio certificate response: " + ex.Message, ex);
        }
    }

    private static X509Certificate2Collection ParseCertificateChainCore(string json)
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

    private static X509Certificate2Collection ParsePemCertificateChain(string pem)
    {
        X509Certificate2Collection collection = new X509Certificate2Collection();
        const string beginMarker = "-----BEGIN CERTIFICATE-----";
        const string endMarker = "-----END CERTIFICATE-----";

        int searchFrom = 0;
        while (true)
        {
            int beginIndex = pem.IndexOf(beginMarker, searchFrom, StringComparison.Ordinal);
            if (beginIndex < 0)
            {
                break;
            }

            int endIndex = pem.IndexOf(endMarker, beginIndex, StringComparison.Ordinal);
            if (endIndex < 0)
            {
                break;
            }

            int b64Start = beginIndex + beginMarker.Length;
            string raw = pem.Substring(b64Start, endIndex - b64Start);
            // Strip all whitespace from PEM base64 content
            StringBuilder b64Builder = new StringBuilder(raw.Length);
            for (int i = 0; i < raw.Length; i++)
            {
                char c = raw[i];
                if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
                {
                    b64Builder.Append(c);
                }
            }

            byte[] der = Convert.FromBase64String(b64Builder.ToString());
#if NET9_0_OR_GREATER
            collection.Add(X509CertificateLoader.LoadCertificate(der));
#else
            collection.Add(new X509Certificate2(der));
#endif
            searchFrom = endIndex + endMarker.Length;
        }

        if (collection.Count == 0)
        {
            throw new FulcioException("Fulcio PEM response contains no certificates.");
        }

        return collection;
    }
}
