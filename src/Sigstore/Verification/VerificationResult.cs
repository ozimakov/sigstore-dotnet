using System.Security.Cryptography.X509Certificates;
using Dev.Sigstore.Rekor.V1;

namespace Sigstore.Verification;

/// <summary>
/// Outcome of Sigstore bundle verification.
/// </summary>
public sealed record VerificationResult
{
    /// <summary>
    /// Creates a verification result.
    /// </summary>
    /// <param name="isSuccess">Whether verification succeeded.</param>
    /// <param name="signerIdentity">Resolved signer identity material.</param>
    /// <param name="certificateChain">Validated chain (leaf first).</param>
    /// <param name="transparencyLogEntry">Transparency log evidence retained from the bundle.</param>
    /// <param name="verificationSteps">Ordered audit trail of successful steps.</param>
    public VerificationResult(
        bool isSuccess,
        SignerIdentity signerIdentity,
        IReadOnlyList<X509Certificate2> certificateChain,
        TransparencyLogEntry transparencyLogEntry,
        IReadOnlyList<string> verificationSteps)
    {
        IsSuccess = isSuccess;
        SignerIdentity = signerIdentity;
        CertificateChain = certificateChain;
        TransparencyLogEntry = transparencyLogEntry;
        VerificationSteps = verificationSteps;
    }

    /// <summary>
    /// Whether verification completed successfully.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Signer identity extracted from the Fulcio leaf certificate.
    /// </summary>
    public SignerIdentity SignerIdentity { get; }

    /// <summary>
    /// Certificate chain used for successful verification.
    /// </summary>
    public IReadOnlyList<X509Certificate2> CertificateChain { get; }

    /// <summary>
    /// Transparency log entry embedded in the bundle (audit material).
    /// </summary>
    public TransparencyLogEntry TransparencyLogEntry { get; }

    /// <summary>
    /// Human-readable list of steps that completed successfully prior to returning.
    /// </summary>
    public IReadOnlyList<string> VerificationSteps { get; }
}
