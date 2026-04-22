using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dev.Sigstore.Rekor.V1;

namespace Sigstore.Signing;

/// <summary>
/// Mutable context threaded through the signing pipeline. Never exposed publicly.
/// </summary>
internal sealed class SigningContext
{
    // Inputs
    public required byte[] Artifact { get; init; }

    /// <summary>null for message_signature; content-type for DSSE.</summary>
    public required string? PayloadType { get; init; }

    // Resolved during pipeline

    public string? TrustedRootJson { get; set; }
    public string? OidcAudience { get; set; }
    public string? OidcToken { get; set; }
    public ECDsa? EphemeralKey { get; set; }
    public X509Certificate2Collection? CertificateChain { get; set; }
    public byte[]? Signature { get; set; }
    public TransparencyLogEntry? TransparencyLogEntry { get; set; }
}
