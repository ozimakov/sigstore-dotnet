using Sigstore.Bundle;
using Sigstore.Crypto;
using Sigstore.Fulcio;
using Sigstore.Rekor;
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
        services.AddSingleton<ISystemClock, DefaultSystemClock>();
        services.AddSingleton<IBundleParser, BundleParser>();
        services.AddSingleton<ICertificateVerifier, CertificateVerifier>();
        services.AddSingleton<ITransparencyLogVerifier, TransparencyLogVerifier>();
        services.AddSingleton<ISignatureVerifier, SignatureVerifier>();
        services.AddSingleton<VerificationPipeline>();
        services.AddSingleton<Verifier>();
        services.AddHttpClient<ITufClient, TufClient>();
        return services;
    }
}
