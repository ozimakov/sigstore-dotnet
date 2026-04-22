using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Dev.Sigstore.Trustroot.V1;
using Sigstore.Exceptions;
using X509CertProto = Dev.Sigstore.Common.V1.X509Certificate;

namespace Sigstore.Fulcio;

/// <summary>
/// Validates Fulcio-issued certificate chains against material embedded in <see cref="TrustedRoot"/>.
/// </summary>
public sealed class CertificateVerifier : ICertificateVerifier
{
    /// <inheritdoc />
    public IReadOnlyList<X509Certificate2> BuildVerifiedChain(X509Certificate2 leaf, TrustedRoot trustedRoot)
    {
        using X509Chain chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        // IgnoreNotTimeValid: Sigstore certs are short-lived and typically expired at
        // verification time. Temporal validity is checked separately using the Rekor
        // integrated time or RFC 3161 timestamp (Step 5 of the verification pipeline).
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.AllowUnknownCertificateAuthority |
            X509VerificationFlags.IgnoreNotTimeValid;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Clear();

        for (int i = 0; i < trustedRoot.CertificateAuthorities.Count; i++)
        {
            CertificateAuthority authority = trustedRoot.CertificateAuthorities[i];
            for (int c = 0; c < authority.CertChain.Certificates.Count; c++)
            {
                X509CertProto cert = authority.CertChain.Certificates[c];
                byte[] der = cert.RawBytes.ToByteArray();
#if NET9_0_OR_GREATER
                chain.ChainPolicy.CustomTrustStore.Add(X509CertificateLoader.LoadCertificate(der));
#else
                chain.ChainPolicy.CustomTrustStore.Add(new X509Certificate2(der));
#endif
            }
        }

        bool ok = chain.Build(leaf);
        if (!ok)
        {
            string detail = "unknown";
            if (chain.ChainStatus.Length > 0)
            {
                detail = chain.ChainStatus[0].StatusInformation;
            }

            throw new CertificateValidationException($"Step 3 (certificate chain): could not build a chain to a trusted Fulcio root. First error: {detail}.");
        }

        List<X509Certificate2> ordered = new List<X509Certificate2>();
        foreach (X509ChainElement element in chain.ChainElements)
        {
            ordered.Add(element.Certificate);
        }

        return ordered;
    }
}

/// <summary>
/// Fulcio chain validation against a Sigstore <see cref="TrustedRoot"/>.
/// </summary>
public interface ICertificateVerifier
{
    /// <summary>
    /// Builds a verified chain for the leaf certificate using trusted Fulcio material.
    /// </summary>
    /// <param name="leaf">Leaf signing certificate.</param>
    /// <param name="trustedRoot">Trusted root metadata.</param>
    /// <returns>Chain ordered from leaf to trust anchor.</returns>
    IReadOnlyList<X509Certificate2> BuildVerifiedChain(X509Certificate2 leaf, TrustedRoot trustedRoot);
}
