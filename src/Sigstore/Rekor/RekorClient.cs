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
        string hexDigest = Convert.ToHexString(artifactDigest).ToLowerInvariant();
        string sigB64 = Convert.ToBase64String(signature);
        string certPem = Convert.ToBase64String(leafCert.RawData);

        string body = $@"{{
  ""kind"": ""hashedrekord"",
  ""apiVersion"": ""0.0.1"",
  ""spec"": {{
    ""signature"": {{
      ""content"": ""{sigB64}"",
      ""publicKey"": {{""content"": ""{certPem}""}}
    }},
    ""data"": {{
      ""hash"": {{""algorithm"": ""sha256"", ""value"": ""{hexDigest}""}}
    }}
  }}
}}";
        return PostEntryAsync(body, cancellationToken);
    }

    /// <inheritdoc/>
    public Task<TransparencyLogEntry> AddDsseEntryAsync(
        byte[] envelopeJson,
        X509Certificate2 leafCert,
        CancellationToken cancellationToken)
    {
        string envelopeB64 = Convert.ToBase64String(envelopeJson);
        string certPem = Convert.ToBase64String(leafCert.RawData);

        string body = $@"{{
  ""kind"": ""dsse"",
  ""apiVersion"": ""0.0.1"",
  ""spec"": {{
    ""proposedContent"": {{
      ""envelope"": ""{envelopeB64}"",
      ""verifiers"": [""{certPem}""]
    }}
  }}
}}";
        return PostEntryAsync(body, cancellationToken);
    }

    private async Task<TransparencyLogEntry> PostEntryAsync(string bodyJson, CancellationToken cancellationToken)
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
                throw new RekorException($"Rekor returned HTTP {(int)response.StatusCode}: {errorBody}");
            }

            string json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            return ParseTransparencyLogEntry(json);
        }
    }

    private static TransparencyLogEntry ParseTransparencyLogEntry(string json)
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
            KindVersion = new KindVersion { Kind = "hashedrekord", Version = "0.0.1" },
            CanonicalizedBody = ByteString.CopyFrom(bodyBytes),
            InclusionPromise = new InclusionPromise
            {
                SignedEntryTimestamp = ByteString.CopyFrom(setBytes)
            }
        };
    }
}
