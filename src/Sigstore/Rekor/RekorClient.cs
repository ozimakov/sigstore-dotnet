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
    private readonly string _hashedRekordVersion;

    /// <summary>Creates a Rekor client.</summary>
    public RekorClient(HttpClient httpClient, Uri baseUrl, string hashedRekordVersion = "0.0.1")
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(baseUrl);
        _httpClient = httpClient;
        _baseUrl = baseUrl;
        _hashedRekordVersion = hashedRekordVersion;
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

        string body;
        if (_hashedRekordVersion == "0.0.2")
        {
            // Rekor v2 API format: /api/v2/log/entries
            string digestB64 = Convert.ToBase64String(artifactDigest);
            string certDerB64 = Convert.ToBase64String(leafCert.RawData);
            body = JsonSerializer.Serialize(new
            {
                hashedRekordRequestV002 = new
                {
                    digest = digestB64,
                    signature = new
                    {
                        content = sigB64,
                        verifier = new
                        {
                            x509Certificate = new { rawBytes = certDerB64 },
                            keyDetails = "PKIX_ECDSA_P256_SHA_256"
                        }
                    }
                }
            });
        }
        else
        {
            // Rekor v1 API format: /api/v1/log/entries
            body = JsonSerializer.Serialize(new
            {
                kind = "hashedrekord",
                apiVersion = _hashedRekordVersion,
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
        }

        return PostEntryAsync(body, "hashedrekord", _hashedRekordVersion, cancellationToken);
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
        string apiPath = _hashedRekordVersion == "0.0.2" ? "api/v2/log/entries" : "api/v1/log/entries";
        Uri endpoint = new Uri(_baseUrl, apiPath);
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
            try
            {
                return ParseTransparencyLogEntry(json, kind, apiVersion);
            }
            catch (RekorException)
            {
                // Include truncated response in error for debugging
                string truncJson = json.Length > 800 ? json[..800] : json;
                throw new RekorException($"Failed to parse Rekor response (first 800 chars): {truncJson}");
            }
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
        // v1 response is {"<uuid>": {...entry fields...}}
        // v2 response may be a direct entry object or protobuf-compatible JSON
        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;

        JsonElement entry;
        if (root.TryGetProperty("logIndex", out _) || root.TryGetProperty("logId", out _))
        {
            // Direct entry object (v2 format or protobuf JSON)
            entry = root;
        }
        else
        {
            // Wrapped format: {"<uuid>": {...}}
            entry = default;
            foreach (JsonProperty prop in root.EnumerateObject())
            {
                entry = prop.Value;
                break;
            }
        }

        if (entry.ValueKind == JsonValueKind.Undefined)
        {
            throw new RekorException("Rekor response is empty.");
        }

        // Try protobuf-style field names first, then v1-style
        long logIndex = 0;
        if (entry.TryGetProperty("logIndex", out JsonElement liEl))
        {
            if (liEl.ValueKind == JsonValueKind.String)
                long.TryParse(liEl.GetString(), out logIndex);
            else
                logIndex = liEl.GetInt64();
        }
        long integratedTime = 0;
        if (entry.TryGetProperty("integratedTime", out JsonElement itEl))
        {
            integratedTime = itEl.GetInt64();
        }
        string logId = entry.GetProperty("logID").GetString() ?? string.Empty;
        string body = entry.GetProperty("body").GetString() ?? string.Empty;

        // Parse actual kind/version from the canonicalized body
        try
        {
            byte[] decodedBody = Convert.FromBase64String(body);
            using JsonDocument bodyDoc = JsonDocument.Parse(decodedBody);
            JsonElement bodyRoot = bodyDoc.RootElement;
            if (bodyRoot.TryGetProperty("kind", out JsonElement bodyKind))
            {
                kind = bodyKind.GetString() ?? kind;
            }
            if (bodyRoot.TryGetProperty("apiVersion", out JsonElement bodyVersion))
            {
                apiVersion = bodyVersion.GetString() ?? apiVersion;
            }
        }
        catch (Exception)
        {
            // Use the passed-in defaults
        }

        string setB64 = string.Empty;
        if (entry.TryGetProperty("verification", out JsonElement verification) &&
            verification.TryGetProperty("signedEntryTimestamp", out JsonElement setElement))
        {
            setB64 = setElement.GetString() ?? string.Empty;
        }

        byte[] logIdBytes = string.IsNullOrEmpty(logId)
            ? Array.Empty<byte>()
            : Convert.FromHexString(logId);

        byte[] setBytes = string.IsNullOrEmpty(setB64)
            ? Array.Empty<byte>()
            : Convert.FromBase64String(setB64);
        byte[] bodyBytes = Convert.FromBase64String(body);

        TransparencyLogEntry result = new TransparencyLogEntry
        {
            LogIndex = logIndex,
            LogId = new Dev.Sigstore.Common.V1.LogId { KeyId = ByteString.CopyFrom(logIdBytes) },
            IntegratedTime = integratedTime,
            KindVersion = new KindVersion { Kind = kind, Version = apiVersion },
            CanonicalizedBody = ByteString.CopyFrom(bodyBytes),
        };

        if (setBytes.Length > 0)
        {
            result.InclusionPromise = new InclusionPromise
            {
                SignedEntryTimestamp = ByteString.CopyFrom(setBytes)
            };
        }

        // Parse inclusion proof if present
        if (verification.ValueKind != JsonValueKind.Undefined &&
            verification.TryGetProperty("inclusionProof", out JsonElement proofEl))
        {
            InclusionProof proof = new InclusionProof();
            if (proofEl.TryGetProperty("logIndex", out JsonElement pLogIdx))
            {
                proof.LogIndex = pLogIdx.GetInt64();
            }

            if (proofEl.TryGetProperty("treeSize", out JsonElement pTreeSize))
            {
                proof.TreeSize = pTreeSize.GetInt64();
            }

            if (proofEl.TryGetProperty("rootHash", out JsonElement pRootHash))
            {
                string? rh = pRootHash.GetString();
                if (!string.IsNullOrEmpty(rh))
                {
                    proof.RootHash = ByteString.CopyFrom(Convert.FromHexString(rh));
                }
            }

            if (proofEl.TryGetProperty("hashes", out JsonElement pHashes) &&
                pHashes.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement h in pHashes.EnumerateArray())
                {
                    string? hv = h.GetString();
                    if (!string.IsNullOrEmpty(hv))
                    {
                        proof.Hashes.Add(ByteString.CopyFrom(Convert.FromHexString(hv)));
                    }
                }
            }

            if (proofEl.TryGetProperty("checkpoint", out JsonElement pCheckpoint))
            {
                string? ckpt = pCheckpoint.GetString();
                if (!string.IsNullOrEmpty(ckpt))
                {
                    proof.Checkpoint = new Dev.Sigstore.Rekor.V1.Checkpoint { Envelope = ckpt };
                }
            }

            result.InclusionProof = proof;
        }

        return result;
    }

    private static string ConvertToPemBase64(X509Certificate2 cert)
    {
        string pem = "-----BEGIN CERTIFICATE-----\n"
            + Convert.ToBase64String(cert.RawData)
            + "\n-----END CERTIFICATE-----\n";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(pem));
    }
}
