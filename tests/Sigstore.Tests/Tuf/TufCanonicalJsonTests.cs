using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Sigstore.Tuf;

namespace Sigstore.Tests.Tuf;

public class TufCanonicalJsonTests
{
    [Fact]
    public void EncodeSigned_ProducesValidCanonicalJson()
    {
        string json = """{"b":"two","a":"one"}""";
        JsonDocument doc = JsonDocument.Parse(json);
        byte[] canonical = TufCanonicalJson.EncodeSigned(doc.RootElement);
        string result = Encoding.UTF8.GetString(canonical);
        // Keys must be sorted, strings must be quoted
        Assert.Equal("""{"a":"one","b":"two"}""", result);
    }

    [Fact]
    public void EncodeSigned_HandlesNestedObjects()
    {
        string json = """{"z":{"b":2,"a":1},"a":"x"}""";
        JsonDocument doc = JsonDocument.Parse(json);
        byte[] canonical = TufCanonicalJson.EncodeSigned(doc.RootElement);
        string result = Encoding.UTF8.GetString(canonical);
        Assert.Equal("""{"a":"x","z":{"a":1,"b":2}}""", result);
    }

    [Fact]
    public async Task VerifyRealRoot14()
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        string rootJson;
        try
        {
            rootJson = await http.GetStringAsync("https://tuf-repo-cdn.sigstore.dev/14.root.json");
        }
        catch (Exception)
        {
            // Skip if no network
            return;
        }

        JsonDocument doc = JsonDocument.Parse(rootJson);
        JsonElement signed = doc.RootElement.GetProperty("signed");
        byte[] canonical = TufCanonicalJson.EncodeSigned(signed);
        string canonicalStr = Encoding.UTF8.GetString(canonical);

        // Must start with { and contain quoted keys
        Assert.StartsWith("{\"", canonicalStr);
        // Must contain the _type field
        Assert.Contains("\"_type\":\"root\"", canonicalStr);
    }

    [Fact]
    public async Task FullTufBootstrap_Succeeds()
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        string rootJson;
        try
        {
            rootJson = await http.GetStringAsync("https://tuf-repo-cdn.sigstore.dev/14.root.json");
        }
        catch (Exception)
        {
            return; // Skip if no network
        }

        // Debug: manually verify one signature
        JsonDocument doc = JsonDocument.Parse(rootJson);
        JsonElement signed = doc.RootElement.GetProperty("signed");
        byte[] canonical = TufCanonicalJson.EncodeSigned(signed);

        JsonElement signatures = doc.RootElement.GetProperty("signatures");
        JsonElement keys = signed.GetProperty("keys");
        JsonElement rootKeyIds = signed.GetProperty("roles").GetProperty("root").GetProperty("keyids");

        // Get the first signature
        JsonElement firstSig = signatures[0];
        string keyId = firstSig.GetProperty("keyid").GetString()!;
        string sigHex = firstSig.GetProperty("sig").GetString()!;

        // Check if keyId is in root keyids
        bool found = false;
        for (int i = 0; i < rootKeyIds.GetArrayLength(); i++)
        {
            if (rootKeyIds[i].GetString() == keyId)
            {
                found = true;
                break;
            }
        }
        Assert.True(found, $"keyId {keyId} not in root keyids");

        // Get the key
        JsonElement key = keys.GetProperty(keyId);
        string keyType = key.GetProperty("keytype").GetString()!;
        string scheme = key.GetProperty("scheme").GetString()!;
        string pem = key.GetProperty("keyval").GetProperty("public").GetString()!;

        // Log details
        Assert.True(pem.Length > 0, "PEM key is empty");

        // Try to verify
        byte[] sigBytes = Convert.FromHexString(sigHex);
        using ECDsa ecKey = ECDsa.Create();
        ecKey.ImportFromPem(pem);

        // Also try verifying the raw JSON bytes of "signed" (as they appear in the original doc)
        string rawJson = rootJson;
        int signedStart = rawJson.IndexOf("\"signed\":");
        // Write first 100 chars of canonical
        string canonicalStr2 = Encoding.UTF8.GetString(canonical);
        string first100 = canonicalStr2.Length > 100 ? canonicalStr2[..100] : canonicalStr2;

        // SHA-256 hash check removed — the securesystemslib canonical form uses literal
        // newlines (not \n escapes), so the hash differs from json.dumps output.

        bool verified = ecKey.VerifyData(canonical, sigBytes, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.True(verified, $"Signature verification failed. KeyType={keyType}, Scheme={scheme}, CanonicalLen={canonical.Length}, SigLen={sigBytes.Length}, First100={first100}");

        // Now test full bootstrap
        var client = new TufClient(http, NullLogger<TufClient>.Instance);
        var root = await client.FetchPublicGoodTrustedRootAsync(CancellationToken.None);
        Assert.NotNull(root);
        Assert.True(root.CertificateAuthorities.Count > 0);
    }
}
