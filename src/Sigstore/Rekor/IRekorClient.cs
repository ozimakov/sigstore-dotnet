using System.Security.Cryptography.X509Certificates;
using Dev.Sigstore.Rekor.V1;

namespace Sigstore.Rekor;

/// <summary>
/// Client for the Rekor transparency log.
/// </summary>
public interface IRekorClient
{
    /// <summary>
    /// Uploads a hashedrekord entry to Rekor and returns the <see cref="TransparencyLogEntry"/>
    /// containing an inclusion promise (SET).
    /// </summary>
    Task<TransparencyLogEntry> AddHashedRekordEntryAsync(
        byte[] artifactDigest,
        byte[] signature,
        X509Certificate2 leafCert,
        CancellationToken cancellationToken);

    /// <summary>
    /// Uploads a DSSE entry to Rekor and returns the <see cref="TransparencyLogEntry"/>
    /// containing an inclusion promise (SET).
    /// </summary>
    Task<TransparencyLogEntry> AddDsseEntryAsync(
        byte[] envelopeJson,
        X509Certificate2 leafCert,
        CancellationToken cancellationToken);
}
