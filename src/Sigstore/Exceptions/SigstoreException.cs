namespace Sigstore.Exceptions;

/// <summary>
/// Base type for all Sigstore .NET verification failures. Each subtype maps to a specific verification step.
/// </summary>
public class SigstoreException : Exception
{
    /// <summary>
    /// Creates a new <see cref="SigstoreException"/>.
    /// </summary>
    /// <param name="message">Human-readable explanation including which step failed.</param>
    public SigstoreException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Creates a new <see cref="SigstoreException"/> with an inner cause.
    /// </summary>
    /// <param name="message">Human-readable explanation including which step failed.</param>
    /// <param name="innerException">Underlying exception.</param>
    public SigstoreException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// The Sigstore bundle JSON could not be parsed or did not match the protobuf JSON encoding rules.
/// </summary>
public sealed class BundleParseException : SigstoreException
{
    /// <inheritdoc />
    public BundleParseException(string message)
        : base(message)
    {
    }

    /// <inheritdoc />
    public BundleParseException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Trusted material from TUF (or a caller-supplied trusted root) could not be fetched or validated.
/// </summary>
public sealed class TrustedRootException : SigstoreException
{
    /// <inheritdoc />
    public TrustedRootException(string message)
        : base(message)
    {
    }

    /// <inheritdoc />
    public TrustedRootException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Fulcio certificate chain validation failed against the configured certificate authorities.
/// </summary>
public sealed class CertificateValidationException : SigstoreException
{
    /// <inheritdoc />
    public CertificateValidationException(string message)
        : base(message)
    {
    }

    /// <inheritdoc />
    public CertificateValidationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// The signing certificate did not satisfy the caller's identity policy.
/// </summary>
public sealed class IdentityPolicyException : SigstoreException
{
    /// <inheritdoc />
    public IdentityPolicyException(string message)
        : base(message)
    {
    }

    /// <inheritdoc />
    public IdentityPolicyException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Transparency log material (checkpoint, signed entry timestamp, or log metadata) failed verification.
/// </summary>
public sealed class TransparencyLogException : SigstoreException
{
    /// <inheritdoc />
    public TransparencyLogException(string message)
        : base(message)
    {
    }

    /// <inheritdoc />
    public TransparencyLogException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// The Merkle inclusion proof did not connect the leaf hash to the advertised tree head.
/// </summary>
public sealed class InclusionProofException : SigstoreException
{
    /// <inheritdoc />
    public InclusionProofException(string message)
        : base(message)
    {
    }

    /// <inheritdoc />
    public InclusionProofException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Cryptographic verification of the artifact signature against the leaf certificate failed.
/// </summary>
public sealed class SignatureVerificationException : SigstoreException
{
    /// <inheritdoc />
    public SignatureVerificationException(string message)
        : base(message)
    {
    }

    /// <inheritdoc />
    public SignatureVerificationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
