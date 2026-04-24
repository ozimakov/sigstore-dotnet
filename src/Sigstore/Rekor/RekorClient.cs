using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Dev.Sigstore.Rekor.V1;
using Google.Protobuf;
using Sigstore.Exceptions;

namespace Sigstore.Rekor;

/// <summary>
/// Rekor transparency log client using the v1 REST API.
/// </summary>
public sealed class RekorClient : IRekorClient
{
    /// <summary>Named HttpClient key used for DI registration.</summary>
    public const string HttpClientName = "Sigstore.Rekor";

    private readonly HttpClient _httpClient;
    private readonly Uri _baseUrl;

    /// <summary>Creates a Rekor client.</summary>
    public RekorClient(HttpClient httpClient, Uri baseUrl)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(baseUrl);
        _httpClient = httpClient;
        _baseUrl = baseUrl;
    }

    /// <inheritdoc/>
    public Task<TransparencyLogEntry> AddHashedRekordEntryAsync(
        byte[] artifactDigest,
        byte[] signature,
        X509Certificate2 leafCert,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifactDigest);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(leafCert);

        string hexDigest = Convert.ToHexString(artifactDigest).ToLowerInvariant();
        string sigB64 = Convert.ToBase64String(signature);
        string certPem = ConvertToPemBase64(leafCert);

        string body = JsonSerializer.Serialize(new
        {
            kind = "hashedrekord",
            apiVersion = "0.0.2",
            spec = new
            {
                signature = new
                {
                    content = sigB64,
                    publicKey = new { content = certPem }
                },
                data = new
                {
                    hash = new { algorithm = "sha256", value = hexDigest }
                }
            }
        });
        return PostEntryAsync(body, "hashedrekord", "0.0.2", cancellationToken);
    }

    /// <inheritdoc/>
    public Task<TransparencyLogEntry> AddDsseEntryAsync(
        byte[] envelopeJson,
        X509Certificate2 leafCert,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(envelopeJson);
        ArgumentNullException.ThrowIfNull(leafCert);

        string envelopeB64 = Convert.ToBase64String(envelopeJson);
        string certPem = ConvertToPemBase64(leafCert);

        string body = JsonSerializer.Serialize(new
        {
            kind = "dsse",
            apiVersion = "0.0.1",
            spec = new
            {
                proposedContent = new
                {
                    envelope = envelopeB64,
                    verifiers = new[] { certPem }
                }
            }
        });
        return PostEntryAsync(body, "dsse", "0.0.1", cancellationToken);
    }

    private async Task<TransparencyLogEntry> PostEntryAsync(string bodyJson, string kind, string apiVersion, CancellationToken cancellationToken)
    {
        Uri endpoint = new Uri(_baseUrl, "api/v1/log/entries");
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Content = new StringContent(bodyJson, Encoding.UTF8, "application/json");

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new RekorException("Rekor request failed: " + ex.Message, ex);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                string errorBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                string truncated = errorBody.Length > 512 ? errorBody[..512] : errorBody;
                throw new RekorException($"Rekor returned HTTP {(int)response.StatusCode}: {truncated}");
            }

            string json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return ParseTransparencyLogEntry(json, kind, apiVersion);
        }
    }

    private static TransparencyLogEntry ParseTransparencyLogEntry(string json, string kind, string apiVersion)
    {
        try
        {
            return ParseTransparencyLogEntryCore(json, kind, apiVersion);
        }
        catch (RekorException)
        {
            throw;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or KeyNotFoundException or InvalidOperationException)
        {
            throw new RekorException("Failed to parse Rekor response: " + ex.Message, ex);
        }
    }

    private static TransparencyLogEntry ParseTransparencyLogEntryCore(string json, string kind, string apiVersion)
    {
        // Response is {"<uuid>": {...entry fields...}}
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;

        JsonElement entry = default;
        foreach (JsonProperty prop in root.EnumerateObject())
        {
            entry = prop.Value;
            break;
        }

        if (entry.ValueKind == JsonValueKind.Undefined)
        {
            throw new RekorException("Rekor response is empty.");
        }

        long logIndex = entry.GetProperty("logIndex").GetInt64();
        long integratedTime = entry.GetProperty("integratedTime").GetInt64();
        string logId = entry.GetProperty("logID").GetString() ?? string.Empty;
        string body = entry.GetProperty("body").GetString() ?? string.Empty;

        string setB64 = string.Empty;
        if (entry.TryGetProperty("verification", out JsonElement verification) &&
            verification.TryGetProperty("signedEntryTimestamp", out JsonElement setElement))
        {
            setB64 = setElement.GetString() ?? string.Empty;
        }

        if (string.IsNullOrEmpty(setB64))
        {
            throw new RekorException("Rekor response is missing the inclusion promise (signedEntryTimestamp).");
        }

        byte[] logIdBytes = string.IsNullOrEmpty(logId)
            ? Array.Empty<byte>()
            : Convert.FromHexString(logId);

        byte[] setBytes = Convert.FromBase64String(setB64);
        byte[] bodyBytes = Convert.FromBase64String(body);

        return new TransparencyLogEntry
        {
            LogIndex = logIndex,
            LogId = new Dev.Sigstore.Common.V1.LogId { KeyId = ByteString.CopyFrom(logIdBytes) },
            IntegratedTime = integratedTime,
            KindVersion = new KindVersion { Kind = kind, Version = apiVersion },
            CanonicalizedBody = ByteString.CopyFrom(bodyBytes),
            InclusionPromise = new InclusionPromise
            {
                SignedEntryTimestamp = ByteString.CopyFrom(setBytes)
            }
        };
    }

    private static string ConvertToPemBase64(X509Certificate2 cert)
    {
        string pem = "-----BEGIN CERTIFICATE-----\n"
            + Convert.ToBase64String(cert.RawData)
            + "\n-----END CERTIFICATE-----\n";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(pem));
    }
}
