using System.Net.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Sigstore.Bundle;
using Sigstore.Crypto;
using Sigstore.Fulcio;
using Sigstore.Oidc;
using Sigstore.Rekor;
using Sigstore.Signing;
using Sigstore.Time;
using Sigstore.Tuf;
using Sigstore.Verification;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// DI registration helpers for Sigstore .NET.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers default Sigstore verification services.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <returns>The same collection.</returns>
    public static IServiceCollection AddSigstore(this IServiceCollection services)
    {
        services.TryAddSingleton<ISystemClock, DefaultSystemClock>();
        services.TryAddSingleton<IBundleParser, BundleParser>();
        services.TryAddSingleton<ICertificateVerifier, CertificateVerifier>();
        services.TryAddSingleton<ITransparencyLogVerifier, TransparencyLogVerifier>();
        services.TryAddSingleton<ISignatureVerifier, SignatureVerifier>();
        services.TryAddSingleton<VerificationPipeline>();
        services.TryAddSingleton<Verifier>();
        services.AddHttpClient<ITufClient, TufClient>();
        return services;
    }

    /// <summary>
    /// Registers Sigstore signing services (Signer, SigningPipeline, FulcioClient, RekorClient,
    /// AmbientTokenProvider). Also calls <see cref="AddSigstore"/> so callers only need one
    /// registration call.
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configure">Optional callback to override signing options.</param>
    /// <returns>The same collection.</returns>
    public static IServiceCollection AddSigstoreSigning(
        this IServiceCollection services,
        Action<SigstoreSigningOptions>? configure = null)
    {
        services.AddSigstore();

        SigstoreSigningOptions options = new SigstoreSigningOptions();
        configure?.Invoke(options);

        // Register OIDC token provider
        if (options.TokenProvider is not null)
        {
            services.TryAddSingleton<IOidcTokenProvider>(options.TokenProvider);
        }
        else
        {
            services.AddHttpClient("Sigstore.OidcProvider");
            services.TryAddSingleton<IOidcTokenProvider>(sp =>
            {
                IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();
                HttpClient httpClient = factory.CreateClient("Sigstore.OidcProvider");
                return new AmbientTokenProvider(httpClient);
            });
        }

        // Register Fulcio HTTP client and client implementation
        services.AddHttpClient(FulcioClient.HttpClientName);
        services.TryAddSingleton<IFulcioClient>(sp =>
        {
            IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();
            HttpClient httpClient = factory.CreateClient(FulcioClient.HttpClientName);
            httpClient.Timeout = options.HttpTimeout;
            return new FulcioClient(httpClient, options.FulcioUrl);
        });

        // Register Rekor HTTP client and client implementation
        services.AddHttpClient(RekorClient.HttpClientName);
        services.TryAddSingleton<IRekorClient>(sp =>
        {
            IHttpClientFactory factory = sp.GetRequiredService<IHttpClientFactory>();
            HttpClient httpClient = factory.CreateClient(RekorClient.HttpClientName);
            httpClient.Timeout = options.HttpTimeout;
            return new RekorClient(httpClient, options.RekorUrl);
        });

        services.TryAddSingleton<SigningPipeline>();

        services.TryAddSingleton<Signer>(sp =>
        {
            SigningPipeline pipeline = sp.GetRequiredService<SigningPipeline>();
            ITufClient tufClient = sp.GetRequiredService<ITufClient>();
            ILogger<Signer> logger = sp.GetRequiredService<ILogger<Signer>>();
            return new Signer(pipeline, tufClient, options.OidcAudience, logger);
        });

        return services;
    }
}
