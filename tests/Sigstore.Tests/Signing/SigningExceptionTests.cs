using Sigstore.Exceptions;

namespace Sigstore.Tests.Signing;

public sealed class SigningExceptionTests
{
    [Fact]
    public void OidcTokenException_IsSubclassOfSigstoreException()
    {
        var ex = new OidcTokenException("test");
        Assert.IsAssignableFrom<SigstoreException>(ex);
    }

    [Fact]
    public void FulcioException_IsSubclassOfSigstoreException()
    {
        var ex = new FulcioException("test");
        Assert.IsAssignableFrom<SigstoreException>(ex);
    }

    [Fact]
    public void RekorException_IsSubclassOfSigstoreException()
    {
        var ex = new RekorException("test");
        Assert.IsAssignableFrom<SigstoreException>(ex);
    }

    [Fact]
    public void SigningException_IsSubclassOfSigstoreException()
    {
        var ex = new SigningException("test");
        Assert.IsAssignableFrom<SigstoreException>(ex);
    }
}
