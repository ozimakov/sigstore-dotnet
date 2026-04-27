using Sigstore.Verification;

namespace Sigstore.Tests.Verification;

public sealed class VerificationPolicyTests
{
    [Fact]
    public void ForExact_SetsIssuerAndIdentity()
    {
        VerificationPolicy policy = VerificationPolicy.ForExact(
            "https://issuer.example.com", "user@example.com");

        Assert.Equal("https://issuer.example.com", policy.ExpectedOidcIssuer);
        Assert.IsType<CertificateIdentityMatcher.ExactMatch>(policy.CertificateIdentityMatcher);
        var exact = (CertificateIdentityMatcher.ExactMatch)policy.CertificateIdentityMatcher;
        Assert.Equal("user@example.com", exact.Expected);
    }

    [Fact]
    public void ForRegexSubject_SetsIssuerAndPattern()
    {
        VerificationPolicy policy = VerificationPolicy.ForRegexSubject(
            "https://issuer.example.com", "user@.*\\.com");

        Assert.Equal("https://issuer.example.com", policy.ExpectedOidcIssuer);
        Assert.IsType<CertificateIdentityMatcher.RegexMatch>(policy.CertificateIdentityMatcher);
    }

    [Fact]
    public void ForGitHubActions_SetsIssuerAndPattern()
    {
        VerificationPolicy policy = VerificationPolicy.ForGitHubActions(
            "https://token.actions.githubusercontent.com", "my-org/my-repo");

        Assert.Equal("https://token.actions.githubusercontent.com", policy.ExpectedOidcIssuer);
    }
}
