using System.Security.Cryptography.X509Certificates;

namespace Sigstore.Fulcio;

/// <summary>
/// Client for the Fulcio certificate authority.
/// </summary>
public interface IFulcioClient
{
    /// <summary>
    /// Requests a signing certificate from Fulcio.
    /// </summary>
    /// <param name="csrDer">DER-encoded PKCS#10 certificate signing request.</param>
    /// <param name="idToken">OIDC identity token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Certificate chain (leaf first).</returns>
    Task<X509Certificate2Collection> GetSigningCertificateAsync(
        byte[] csrDer, string idToken, CancellationToken cancellationToken);
}
