using Sigstore.Exceptions;

namespace Sigstore.Tests.Exceptions;

public sealed class SigstoreExceptionTests
{
    public static TheoryData<Func<string, SigstoreException>, Func<string, Exception, SigstoreException>> Constructors =>
        new()
        {
            { msg => new SigstoreException(msg), (msg, inner) => new SigstoreException(msg, inner) },
            { msg => new BundleParseException(msg), (msg, inner) => new BundleParseException(msg, inner) },
            { msg => new TrustedRootException(msg), (msg, inner) => new TrustedRootException(msg, inner) },
            { msg => new CertificateValidationException(msg), (msg, inner) => new CertificateValidationException(msg, inner) },
            { msg => new IdentityPolicyException(msg), (msg, inner) => new IdentityPolicyException(msg, inner) },
            { msg => new TransparencyLogException(msg), (msg, inner) => new TransparencyLogException(msg, inner) },
            { msg => new InclusionProofException(msg), (msg, inner) => new InclusionProofException(msg, inner) },
            { msg => new SignatureVerificationException(msg), (msg, inner) => new SignatureVerificationException(msg, inner) },
            { msg => new OidcTokenException(msg), (msg, inner) => new OidcTokenException(msg, inner) },
            { msg => new FulcioException(msg), (msg, inner) => new FulcioException(msg, inner) },
            { msg => new RekorException(msg), (msg, inner) => new RekorException(msg, inner) },
            { msg => new SigningException(msg), (msg, inner) => new SigningException(msg, inner) },
        };

    [Theory]
    [MemberData(nameof(Constructors))]
    public void MessageCtor_PreservesMessage(
        Func<string, SigstoreException> messageCtor,
        Func<string, Exception, SigstoreException> innerCtor)
    {
        SigstoreException ex = messageCtor("step failed");
        Assert.Equal("step failed", ex.Message);
        Assert.Null(ex.InnerException);
        Assert.IsAssignableFrom<SigstoreException>(ex);
        _ = innerCtor;
    }

    [Theory]
    [MemberData(nameof(Constructors))]
    public void InnerCtor_PreservesMessageAndInnerException(
        Func<string, SigstoreException> messageCtor,
        Func<string, Exception, SigstoreException> innerCtor)
    {
        InvalidOperationException root = new("root cause");
        SigstoreException ex = innerCtor("wrapping", root);
        Assert.Equal("wrapping", ex.Message);
        Assert.Same(root, ex.InnerException);
        _ = messageCtor;
    }
}
