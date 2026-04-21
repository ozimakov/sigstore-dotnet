namespace Sigstore.Verification;

/// <summary>
/// Identity-oriented view of a Fulcio leaf certificate.
/// </summary>
public sealed record SignerIdentity
{
    /// <summary>
    /// Creates a signer identity snapshot.
    /// </summary>
    public SignerIdentity(string oidcIssuer, string subject, string? subjectAlternativeNameUri)
    {
        OidcIssuer = oidcIssuer;
        Subject = subject;
        SubjectAlternativeNameUri = subjectAlternativeNameUri;
    }

    /// <summary>OIDC issuer URI.</summary>
    public string OidcIssuer { get; }

    /// <summary>Subject string used for policy checks.</summary>
    public string Subject { get; }

    /// <summary>SAN URI, when available.</summary>
    public string? SubjectAlternativeNameUri { get; }
}
