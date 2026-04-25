using Dev.Sigstore.Trustroot.V1;
using Microsoft.Extensions.Logging.Abstractions;
using Sigstore.Bundle;
using Sigstore.Crypto;
using Sigstore.Fulcio;
using Sigstore.Oidc;
using Sigstore.Rekor;
using Sigstore.Signing;
using Sigstore.Time;
using Sigstore.Tuf;
using Sigstore.Verification;

namespace Sigstore.Conformance;

/// <summary>
/// CLI entrypoint implementing the <c>sigstore-conformance</c> client-under-test protocol.
/// See <see href="https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md">cli_protocol.md</see>.
/// </summary>
public static class ConformanceRunner
{
    /// <summary>
    /// CLI implementation invoked from <see cref="Program"/>.
    /// </summary>
    /// <param name="args">Raw arguments (excluding process name).</param>
    /// <returns>Process exit code.</returns>
    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0)
        {
            await Console.Error.WriteLineAsync("usage: sigstore-dotnet <sign-bundle|verify-bundle> ...").ConfigureAwait(false);
            return 2;
        }

        string command = args[0];
        if (string.Equals(command, "sign-bundle", StringComparison.OrdinalIgnoreCase))
        {
            return await RunSignAsync(args.AsMemory(1)).ConfigureAwait(false);
        }

        if (!string.Equals(command, "verify-bundle", StringComparison.OrdinalIgnoreCase))
        {
            await Console.Error.WriteLineAsync($"unknown command: {command}").ConfigureAwait(false);
            return 2;
        }

        return await RunVerifyAsync(args.AsMemory(1)).ConfigureAwait(false);
    }

    private static async Task<int> RunVerifyAsync(ReadOnlyMemory<string> args)
    {
        bool staging = false;
        string? bundlePath = null;
        string? certificateIdentity = null;
        string? certificateOidcIssuer = null;
        string? keyPath = null;
        string? trustedRootPath = null;
        string? fileOrDigest = null;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args.Span[i];
            if (string.Equals(a, "--staging", StringComparison.Ordinal))
            {
                staging = true;
                continue;
            }

            if (string.Equals(a, "--bundle", StringComparison.Ordinal) && i + 1 < args.Length)
            {
                bundlePath = args.Span[++i];
                continue;
            }

            if (string.Equals(a, "--certificate-identity", StringComparison.Ordinal) && i + 1 < args.Length)
            {
                certificateIdentity = args.Span[++i];
                continue;
            }

            if (string.Equals(a, "--certificate-oidc-issuer", StringComparison.Ordinal) && i + 1 < args.Length)
            {
                certificateOidcIssuer = args.Span[++i];
                continue;
            }

            if (string.Equals(a, "--key", StringComparison.Ordinal) && i + 1 < args.Length)
            {
                keyPath = args.Span[++i];
                continue;
            }

            if (string.Equals(a, "--trusted-root", StringComparison.Ordinal) && i + 1 < args.Length)
            {
                trustedRootPath = args.Span[++i];
                continue;
            }

            if (fileOrDigest is null)
            {
                fileOrDigest = a;
            }
        }

        if (bundlePath is null || fileOrDigest is null)
        {
            await Console.Error.WriteLineAsync("verify-bundle requires --bundle and FILE_OR_DIGEST").ConfigureAwait(false);
            return 2;
        }

        _ = staging;

        string bundleJson = await File.ReadAllTextAsync(bundlePath).ConfigureAwait(false);
        ReadOnlyMemory<byte> artifact = await LoadArtifactOrDigestAsync(fileOrDigest).ConfigureAwait(false);

        string? trustedRootJson = null;
        if (trustedRootPath is not null)
        {
            trustedRootJson = await File.ReadAllTextAsync(trustedRootPath).ConfigureAwait(false);
        }

        Verifier verifier = CreateVerifier();
        try
        {
            if (keyPath is not null)
            {
                // Managed-key verification: skip Fulcio chain + identity policy
                VerificationPolicy anyPolicy = VerificationPolicy.ForExact("*", "*");
                string keyPem = await File.ReadAllTextAsync(keyPath).ConfigureAwait(false);
                VerificationResult result = await verifier.VerifyWithKeyAsync(
                    bundleJson, artifact, keyPem, trustedRootJson, CancellationToken.None).ConfigureAwait(false);
                if (!result.IsSuccess)
                {
                    return 1;
                }

                return 0;
            }

            if (certificateIdentity is null || certificateOidcIssuer is null)
            {
                await Console.Error.WriteLineAsync("verify-bundle requires --certificate-identity and --certificate-oidc-issuer for keyless bundles.").ConfigureAwait(false);
                return 2;
            }

            VerificationPolicy policy = VerificationPolicy.ForExact(certificateOidcIssuer, certificateIdentity);
            VerificationResult keylessResult = await verifier.VerifyAsync(
                bundleJson, artifact, policy, trustedRootJson, CancellationToken.None).ConfigureAwait(false);
            if (!keylessResult.IsSuccess)
            {
                return 1;
            }

            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(ex.ToString()).ConfigureAwait(false);
            return 1;
        }
    }

    private static async Task<int> RunSignAsync(ReadOnlyMemory<string> args)
    {
        string? identityToken = null;
        string? bundleOutputPath = null;
        string? artifactPath = null;
        string? trustedRootPath = null;
        string? signingConfigPath = null;

        for (int i = 0; i < args.Length; i++)
        {
            string a = args.Span[i];
            if (string.Equals(a, "--identity-token", StringComparison.Ordinal) && i + 1 < args.Length)
            {
                identityToken = args.Span[++i];
                continue;
            }

            if (string.Equals(a, "--bundle", StringComparison.Ordinal) && i + 1 < args.Length)
            {
                bundleOutputPath = args.Span[++i];
                continue;
            }

            if (string.Equals(a, "--trusted-root", StringComparison.Ordinal) && i + 1 < args.Length)
            {
                trustedRootPath = args.Span[++i];
                continue;
            }

            if (string.Equals(a, "--signing-config", StringComparison.Ordinal) && i + 1 < args.Length)
            {
                signingConfigPath = args.Span[++i];
                continue;
            }

            if (a.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            if (artifactPath is null)
            {
                artifactPath = a;
            }
        }

        if (identityToken is null || bundleOutputPath is null || artifactPath is null)
        {
            await Console.Error.WriteLineAsync("sign-bundle requires --identity-token, --bundle, and FILE").ConfigureAwait(false);
            return 2;
        }

        byte[] artifact = await File.ReadAllBytesAsync(artifactPath).ConfigureAwait(false);

        using HttpClient http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        // Determine trusted root
        TrustedRoot trustedRoot;
        if (trustedRootPath is not null)
        {
            string trJson = await File.ReadAllTextAsync(trustedRootPath).ConfigureAwait(false);
            var parser = new Google.Protobuf.JsonParser(
                Google.Protobuf.JsonParser.Settings.Default.WithIgnoreUnknownFields(true));
            trustedRoot = parser.Parse<TrustedRoot>(trJson);
        }
        else
        {
            TufClient tufClient = new TufClient(http, NullLogger<TufClient>.Instance);
            trustedRoot = await tufClient.FetchPublicGoodTrustedRootAsync(CancellationToken.None).ConfigureAwait(false);
        }

        // Determine signing endpoints from signing config or defaults
        Uri fulcioUrl = new Uri("https://fulcio.sigstore.dev/");
        Uri rekorUrl = new Uri("https://rekor.sigstore.dev/");
        Uri? tsaUrl = null;

        if (signingConfigPath is not null)
        {
            string scJson = await File.ReadAllTextAsync(signingConfigPath).ConfigureAwait(false);
            var parser = new Google.Protobuf.JsonParser(
                Google.Protobuf.JsonParser.Settings.Default.WithIgnoreUnknownFields(true));
            var signingConfig = parser.Parse<Dev.Sigstore.Trustroot.V1.SigningConfig>(scJson);

            // Select the first valid CA URL
            foreach (var ca in signingConfig.CaUrls)
            {
                if (!string.IsNullOrEmpty(ca.Url))
                {
                    fulcioUrl = new Uri(ca.Url.TrimEnd('/') + "/");
                    break;
                }
            }

            // Select the first valid Rekor URL
            foreach (var tlog in signingConfig.RekorTlogUrls)
            {
                if (!string.IsNullOrEmpty(tlog.Url))
                {
                    rekorUrl = new Uri(tlog.Url.TrimEnd('/') + "/");
                    break;
                }
            }

            // Select the first valid TSA URL
            foreach (var tsa in signingConfig.TsaUrls)
            {
                if (!string.IsNullOrEmpty(tsa.Url))
                {
                    tsaUrl = new Uri(tsa.Url.TrimEnd('/') + "/");
                    break;
                }
            }
        }

        SigningPipeline pipeline = new SigningPipeline(
            new StaticTokenProvider(identityToken),
            new FulcioClient(http, fulcioUrl),
            new RekorClient(http, rekorUrl),
            new CertificateVerifier(),
            NullLogger<SigningPipeline>.Instance);

        try
        {
            SigningResult result = await pipeline.RunAsync(
                artifact, payloadType: null, "sigstore", trustedRoot,
                tsaUrl: tsaUrl, httpClient: http,
                CancellationToken.None).ConfigureAwait(false);
            await File.WriteAllTextAsync(bundleOutputPath, result.BundleJson).ConfigureAwait(false);
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(ex.ToString()).ConfigureAwait(false);
            return 1;
        }
    }

    private static Verifier CreateVerifier()
    {
        HttpClient http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        Verifier verifier = new Verifier(
            new VerificationPipeline(
                new BundleParser(),
                new CertificateVerifier(),
                new TransparencyLogVerifier(),
                new SignatureVerifier(),
                new DefaultSystemClock(),
                NullLogger<VerificationPipeline>.Instance),
            new TufClient(http, NullLogger<TufClient>.Instance),
            NullLogger<Verifier>.Instance);
        return verifier;
    }

    private static async Task<ReadOnlyMemory<byte>> LoadArtifactOrDigestAsync(string fileOrDigest)
    {
        if (fileOrDigest.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase) && fileOrDigest.Length == 7 + 64)
        {
            return Convert.FromHexString(fileOrDigest.AsSpan(7));
        }

        byte[] bytes = await File.ReadAllBytesAsync(fileOrDigest).ConfigureAwait(false);
        return bytes;
    }
}
