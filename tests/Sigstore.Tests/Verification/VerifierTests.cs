using Sigstore.Verification;

namespace Sigstore.Tests.Verification;

public sealed class VerifierTests
{
    [Fact]
    public void Given_DefaultPolicyBuilder_When_ForExact_Then_IssuerIsSet()
    {
        VerificationPolicy policy = VerificationPolicy.ForExact("https://issuer", "sub");
        Assert.Equal("https://issuer", policy.ExpectedOidcIssuer);
    }
}
