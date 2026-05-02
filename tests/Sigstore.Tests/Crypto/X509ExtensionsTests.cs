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

    [Fact]
    public void TryGetFulcioStringExtension_PresentOctetStringWrappedUtf8_DecodesValue()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);
        // Fulcio stores OIDC issuer (.8) as DER OCTET STRING wrapping a UTF8String.
        byte[] raw = EncodeOctetStringWrappedUtf8("https://accounts.example.com");
        req.CertificateExtensions.Add(new X509Extension(X509Extensions.OidcIssuerOid, raw, critical: false));
        X509Certificate2 cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        bool found = X509Extensions.TryGetFulcioStringExtension(cert, X509Extensions.OidcIssuerOid, out string value);

        Assert.True(found);
        Assert.Equal("https://accounts.example.com", value);
    }

    [Fact]
    public void TryGetPrimaryIdentityUri_NoSan_ReturnsFalse()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        X509Certificate2 cert = CreateSelfSigned(key);

        bool found = X509Extensions.TryGetPrimaryIdentityUri(cert, out string identity);

        Assert.False(found);
        Assert.Equal(string.Empty, identity);
    }

    [Fact]
    public void TryGetPrimaryIdentityUri_WithUriSan_ReturnsFirstUri()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(new Uri("https://github.com/owner/repo/.github/workflows/release.yml@refs/heads/main"));
        sanBuilder.AddUri(new Uri("https://github.com/owner/repo/.github/workflows/secondary.yml@refs/heads/main"));
        req.CertificateExtensions.Add(sanBuilder.Build());
        X509Certificate2 cert = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        bool found = X509Extensions.TryGetPrimaryIdentityUri(cert, out string identity);

        Assert.True(found);
        Assert.StartsWith("https://github.com/owner/repo/.github/workflows/", identity);
    }

    private static byte[] EncodeOctetStringWrappedUtf8(string value)
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        var inner = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        inner.WriteCharacterString(System.Formats.Asn1.UniversalTagNumber.UTF8String, value);
        writer.WriteOctetString(inner.Encode());
        return writer.Encode();
    }

    private static X509Certificate2 CreateSelfSigned(ECDsa key)
    {
        var req = new CertificateRequest("CN=test", key, HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
