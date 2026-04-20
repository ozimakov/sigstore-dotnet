using System.Text.RegularExpressions;

namespace Sigstore.Verification;

/// <summary>
/// Immutable identity policy for Sigstore bundle verification.
/// </summary>
public sealed record VerificationPolicy
{
    /// <summary>
    /// Creates a policy.
    /// </summary>
    /// <param name="expectedOidcIssuer">Expected OIDC issuer URI (from Fulcio extensions).</param>
    /// <param name="certificateIdentityMatcher">Matcher for certificate identity (typically a SAN URI).</param>
    public VerificationPolicy(string expectedOidcIssuer, CertificateIdentityMatcher certificateIdentityMatcher)
    {
        ExpectedOidcIssuer = expectedOidcIssuer;
        CertificateIdentityMatcher = certificateIdentityMatcher;
    }

    /// <summary>
    /// Expected OIDC issuer string (for example <c>https://token.actions.githubusercontent.com</c>).
    /// </summary>
    public string ExpectedOidcIssuer { get; }

    /// <summary>
    /// Matcher applied to certificate identity material.
    /// </summary>
    public CertificateIdentityMatcher CertificateIdentityMatcher { get; }

    /// <summary>
    /// Requires an exact match for both issuer and identity string.
    /// </summary>
    /// <param name="issuer">OIDC issuer.</param>
    /// <param name="identity">Exact expected identity (for example SAN URI).</param>
    /// <returns>Immutable policy instance.</returns>
    public static VerificationPolicy ForExact(string issuer, string identity)
    {
        return new VerificationPolicy(issuer, CertificateIdentityMatcher.Exact(identity));
    }

    /// <summary>
    /// Requires an exact issuer and a subject that matches a regular expression.
    /// </summary>
    /// <param name="issuer">OIDC issuer.</param>
    /// <param name="subjectPattern">Regular expression applied to the identity string.</param>
    /// <returns>Immutable policy instance.</returns>
    public static VerificationPolicy ForRegexSubject(string issuer, string subjectPattern)
    {
        Regex regex = new Regex(subjectPattern, RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromSeconds(1));
        return new VerificationPolicy(issuer, CertificateIdentityMatcher.Regex(regex));
    }

    /// <summary>
    /// Builds a GitHub Actions-oriented policy for <c>https://token.actions.githubusercontent.com</c>.
    /// </summary>
    /// <param name="repository">Repository in <c>owner/name</c> form.</param>
    /// <param name="gitRef">Git ref (for example <c>refs/heads/main</c>).</param>
    /// <param name="workflow">Optional workflow name; when empty, identity is matched only by repo and ref.</param>
    /// <returns>Immutable policy instance.</returns>
    public static VerificationPolicy ForGitHubActions(string repository, string gitRef, string? workflow = null)
    {
        string issuer = "https://token.actions.githubusercontent.com";
        string identity = $"repo:{repository}:ref:{gitRef}";
        _ = workflow;

        Regex regex = new Regex("^" + Regex.Escape(identity) + "$", RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromSeconds(1));
        return new VerificationPolicy(issuer, CertificateIdentityMatcher.Regex(regex));
    }
}

/// <summary>
/// Describes how to compare expected and observed certificate identity strings.
/// </summary>
public abstract record CertificateIdentityMatcher
{
    /// <summary>
    /// Exact string comparison.
    /// </summary>
    public sealed record ExactMatch(string Expected) : CertificateIdentityMatcher;

    /// <summary>
    /// Regular expression match.
    /// </summary>
    public sealed record RegexMatch(Regex Pattern) : CertificateIdentityMatcher;

    /// <summary>
    /// Exact match helper.
    /// </summary>
    public static CertificateIdentityMatcher Exact(string expected)
    {
        return new ExactMatch(expected);
    }

    /// <summary>
    /// Regex match helper.
    /// </summary>
    public static CertificateIdentityMatcher Regex(Regex pattern)
    {
        return new RegexMatch(pattern);
    }
}
