using Sigstore.Verification;

namespace Sigstore.Tests.Verification;

public sealed class VerificationPipelineTests
{
    [Fact]
    public void Given_PolicyExact_When_SubjectsEqual_Then_PolicyMatches()
    {
        VerificationPolicy policy = VerificationPolicy.ForExact("https://issuer.example", "identity");
        Assert.Equal("https://issuer.example", policy.ExpectedOidcIssuer);
    }
}
