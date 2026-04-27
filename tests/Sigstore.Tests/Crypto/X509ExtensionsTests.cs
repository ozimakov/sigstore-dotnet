using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sigstore.Crypto;

namespace Sigstore.Tests.Crypto;

public sealed class X509ExtensionsTests
{
    [Fact]
    public void OidConstants_HaveExpectedValues()
    {
        Assert.Equal("1.3.6.1.4.1.57264.1.1", X509Extensions.OidcIssuerOidLegacy);
        Assert.Equal("1.3.6.1.4.1.57264.1.8", X509Extensions.OidcIssuerOid);
        Assert.Equal("1.3.6.1.4.1.57264.1.24", X509Extensions.OidcTokenSubjectOid);
        Assert.Equal("1.3.6.1.4.1.57264.1.7", X509Extensions.FulcioOtherNameOid);
    }

    [Fact]
    public void TryGetFulcioStringExtension_MissingOid_ReturnsFalse()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 cert = CreateSelfSigned(key);

        bool found = X509Extensions.TryGetFulcioStringExtension(
            cert, X509Extensions.OidcIssuerOid, out string value);

        Assert.False(found);
        Assert.Equal(string.Empty, value);
    }

    [Fact]
    public void GetSubjectAlternativeNameUris_NoSan_ReturnsEmpty()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 cert = CreateSelfSigned(key);

        IReadOnlyList<string> uris = X509Extensions.GetSubjectAlternativeNameUris(cert);

        Assert.Empty(uris);
    }

    [Fact]
    public void GetSubjectAlternativeNameUris_WithUriSan_ReturnsUri()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri("https://github.com/test/workflow.yml@refs/heads/main"));
        req.CertificateExtensions.Add(sanBuilder.Build());
        X509Certificate2 cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        IReadOnlyList<string> uris = X509Extensions.GetSubjectAlternativeNameUris(cert);

        Assert.Contains("https://github.com/test/workflow.yml@refs/heads/main", uris);
    }

    private static X509Certificate2 CreateSelfSigned(ECDsa key)
    {
        var req = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
