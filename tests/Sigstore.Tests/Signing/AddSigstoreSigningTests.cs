using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sigstore.Fulcio;
using Sigstore.Oidc;
using Sigstore.Rekor;
using Sigstore.Signing;
using Sigstore.Verification;

namespace Sigstore.Tests.Signing;

public sealed class AddSigstoreSigningTests
{
    [Fact]
    public void AddSigstoreSigning_RegistersSigner()
    {
        ServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddSigstoreSigning();

        ServiceProvider provider = services.BuildServiceProvider();
        Signer signer = provider.GetRequiredService<Signer>();
        Assert.NotNull(signer);
    }

    [Fact]
    public void AddSigstoreSigning_RegistersSigningPipeline()
    {
        ServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddSigstoreSigning();

        ServiceProvider provider = services.BuildServiceProvider();
        SigningPipeline pipeline = provider.GetRequiredService<SigningPipeline>();
        Assert.NotNull(pipeline);
    }

    [Fact]
    public void AddSigstoreSigning_RegistersVerifierToo()
    {
        ServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddSigstoreSigning();

        ServiceProvider provider = services.BuildServiceProvider();
        Verifier verifier = provider.GetRequiredService<Verifier>();
        Assert.NotNull(verifier);
    }

    [Fact]
    public void AddSigstoreSigning_WithCustomTokenProvider_UsesIt()
    {
        ServiceCollection services = new ServiceCollection();
        services.AddLogging();
        StaticTokenProvider customProvider = new StaticTokenProvider("my.jwt.token");
        services.AddSigstoreSigning(o => o.TokenProvider = customProvider);

        ServiceProvider provider = services.BuildServiceProvider();
        IOidcTokenProvider tokenProvider = provider.GetRequiredService<IOidcTokenProvider>();
        Assert.Same(customProvider, tokenProvider);
    }

    [Fact]
    public void AddSigstoreSigning_CalledTwice_DoesNotThrow()
    {
        ServiceCollection services = new ServiceCollection();
        services.AddLogging();
        services.AddSigstoreSigning();
        services.AddSigstoreSigning(); // second call — must be idempotent for singleton registrations

        // Should not throw
        ServiceProvider provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetRequiredService<Signer>());
    }
}
