using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dev.Sigstore.Trustroot.V1;
using Microsoft.Extensions.Logging;
using Sigstore.Exceptions;

namespace Sigstore.Tuf;

/// <summary>
/// Minimal TUF client for the Sigstore Public Good Instance that bootstraps from a versioned root
/// published on <c>tuf-repo-cdn.sigstore.dev</c>, then refreshes timestamp/snapshot/targets metadata and
/// downloads <c>trusted_root.json</c>.
/// </summary>
public sealed class TufClient : ITufClient
{
    private const string DefaultMirror = "https://tuf-repo-cdn.sigstore.dev/";
    private const int BootstrapRootVersion = 14;

    private readonly HttpClient _httpClient;
    private readonly ILogger<TufClient> _logger;

    /// <summary>
    /// Creates a TUF client.
    /// </summary>
    /// <param name="httpClient">HTTP client used for metadata and target fetches.</param>
    /// <param name="logger">Logger.</param>
    public TufClient(HttpClient httpClient, ILogger<TufClient> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<TrustedRoot> FetchPublicGoodTrustedRootAsync(CancellationToken cancellationToken)
    {
        string mirror = DefaultMirror;
        JsonDocument root = await DownloadMetadataAsync($"{mirror}{BootstrapRootVersion}.root.json", cancellationToken).ConfigureAwait(false);
        VerifyRootSelfSignatures(root, threshold: 3);

        JsonDocument timestamp = await DownloadMetadataAsync($"{mirror}timestamp.json", cancellationToken).ConfigureAwait(false);
        VerifyMetadataAgainstRoot(root, timestamp, "timestamp", threshold: 1);

        int snapshotVersion = GetVersion(timestamp, "snapshot.json");
        JsonDocument snapshot = await DownloadMetadataAsync($"{mirror}{snapshotVersion}.snapshot.json", cancellationToken).ConfigureAwait(false);
        VerifyMetadataAgainstRoot(root, snapshot, "snapshot", threshold: 1);

        int targetsVersion = GetVersion(snapshot, "targets.json");
        JsonDocument targets = await DownloadMetadataAsync($"{mirror}{targetsVersion}.targets.json", cancellationToken).ConfigureAwait(false);
        VerifyMetadataAgainstRoot(root, targets, "targets", threshold: 3);

        string trustedRootHex = GetTargetSha256(targets, "trusted_root.json");
        byte[] trustedRootBytes = await DownloadTargetAsync($"{mirror}targets/{trustedRootHex}.trusted_root.json", cancellationToken).ConfigureAwait(false);
        string trustedRootJson = Encoding.UTF8.GetString(trustedRootBytes);
        _logger.LogInformation("Fetched trusted root JSON from TUF ({Length} bytes).", trustedRootJson.Length);
        return TrustedRootLoader.Parse(trustedRootJson);
    }

    private async Task<JsonDocument> DownloadMetadataAsync(string url, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new TrustedRootException($"Step 2 (trusted root): failed to download TUF metadata from '{url}' (HTTP {(int)response.StatusCode}).");
        }

        await using Stream stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        JsonDocument doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        return doc;
    }

    private async Task<byte[]> DownloadTargetAsync(string url, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new TrustedRootException($"Step 2 (trusted root): failed to download TUF target from '{url}' (HTTP {(int)response.StatusCode}).");
        }

        return await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
    }

    private static void VerifyRootSelfSignatures(JsonDocument rootDocument, int threshold)
    {
        JsonElement signed = rootDocument.RootElement.GetProperty("signed");
        byte[] canonical = TufCanonicalJson.EncodeSigned(signed);
        JsonElement signatures = rootDocument.RootElement.GetProperty("signatures");
        JsonElement keys = signed.GetProperty("keys");
        JsonElement rootKeyIds = signed.GetProperty("roles").GetProperty("root").GetProperty("keyids");

        int valid = 0;
        for (int i = 0; i < signatures.GetArrayLength(); i++)
        {
            JsonElement sig = signatures[i];
            string keyId = sig.GetProperty("keyid").GetString() ?? string.Empty;
            string sigHex = sig.GetProperty("sig").GetString() ?? string.Empty;
            if (sigHex.Length == 0)
            {
                continue;
            }

            bool allowed = false;
            for (int r = 0; r < rootKeyIds.GetArrayLength(); r++)
            {
                if (string.Equals(rootKeyIds[r].GetString(), keyId, StringComparison.Ordinal))
                {
                    allowed = true;
                    break;
                }
            }

            if (!allowed)
            {
                continue;
            }

            if (!keys.TryGetProperty(keyId, out JsonElement key))
            {
                continue;
            }

            string pem = key.GetProperty("keyval").GetProperty("public").GetString() ?? string.Empty;
            byte[] signatureBytes = Convert.FromHexString(sigHex);
            if (TufEcdsaP256Sha256.VerifyPem(pem, canonical, signatureBytes))
            {
                valid++;
            }
        }

        if (valid < threshold)
        {
            throw new TrustedRootException($"Step 2 (trusted root): root metadata signature threshold not met (got {valid}, need {threshold}).");
        }
    }

    private static void VerifyMetadataAgainstRoot(JsonDocument rootDocument, JsonDocument childDocument, string roleName, int threshold)
    {
        JsonElement rootSigned = rootDocument.RootElement.GetProperty("signed");
        JsonElement roles = rootSigned.GetProperty("roles");
        JsonElement role = roles.GetProperty(roleName);
        JsonElement keyIds = role.GetProperty("keyids");
        JsonElement keys = rootSigned.GetProperty("keys");

        JsonElement signed = childDocument.RootElement.GetProperty("signed");
        byte[] canonical = TufCanonicalJson.EncodeSigned(signed);
        JsonElement signatures = childDocument.RootElement.GetProperty("signatures");

        int valid = 0;
        for (int i = 0; i < signatures.GetArrayLength(); i++)
        {
            JsonElement sig = signatures[i];
            string keyId = sig.GetProperty("keyid").GetString() ?? string.Empty;
            string sigHex = sig.GetProperty("sig").GetString() ?? string.Empty;
            if (sigHex.Length == 0)
            {
                continue;
            }

            bool allowed = false;
            for (int k = 0; k < keyIds.GetArrayLength(); k++)
            {
                if (string.Equals(keyIds[k].GetString(), keyId, StringComparison.Ordinal))
                {
                    allowed = true;
                    break;
                }
            }

            if (!allowed)
            {
                continue;
            }

            if (!keys.TryGetProperty(keyId, out JsonElement key))
            {
                continue;
            }

            string pem = key.GetProperty("keyval").GetProperty("public").GetString() ?? string.Empty;
            byte[] signatureBytes = Convert.FromHexString(sigHex);
            if (TufEcdsaP256Sha256.VerifyPem(pem, canonical, signatureBytes))
            {
                valid++;
            }
        }

        if (valid < threshold)
        {
            throw new TrustedRootException($"Step 2 (trusted root): '{roleName}' metadata signature threshold not met (got {valid}, need {threshold}).");
        }
    }

    private static int GetVersion(JsonDocument parent, string childName)
    {
        JsonElement signed = parent.RootElement.GetProperty("signed");
        JsonElement meta = signed.GetProperty("meta");
        JsonElement child = meta.GetProperty(childName);
        return child.GetProperty("version").GetInt32();
    }

    private static string GetTargetSha256(JsonDocument targets, string targetName)
    {
        JsonElement signed = targets.RootElement.GetProperty("signed");
        JsonElement targetMap = signed.GetProperty("targets");
        JsonElement target = targetMap.GetProperty(targetName);
        return target.GetProperty("hashes").GetProperty("sha256").GetString() ?? string.Empty;
    }
}

/// <summary>
/// Fetches the Sigstore Public Good trusted root via TUF.
/// </summary>
public interface ITufClient
{
    /// <summary>
    /// Downloads and verifies TUF metadata, then returns the parsed <see cref="TrustedRoot"/>.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Trusted root protobuf model.</returns>
    Task<TrustedRoot> FetchPublicGoodTrustedRootAsync(CancellationToken cancellationToken);
}

internal static class TufEcdsaP256Sha256
{
    public static bool VerifyPem(string pemPublicKey, ReadOnlySpan<byte> canonicalUtf8, ReadOnlySpan<byte> derSignature)
    {
        using ECDsa key = ECDsa.Create();
        key.ImportFromPem(pemPublicKey);
        // TUF signatures are DER-encoded (RFC 3279), not IEEE P1363
        return key.VerifyData(canonicalUtf8, derSignature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }
}
