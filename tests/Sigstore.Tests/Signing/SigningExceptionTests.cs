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
    public void OidcTokenException_PreservesMessage()
    {
        var ex = new OidcTokenException("OIDC token acquisition failed");
        Assert.Equal("OIDC token acquisition failed", ex.Message);
    }

    [Fact]
    public void OidcTokenException_PreservesInnerException()
    {
        var inner = new InvalidOperationException("inner");
        var ex = new OidcTokenException("outer", inner);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void FulcioException_IsSubclassOfSigstoreException()
    {
        var ex = new FulcioException("test");
        Assert.IsAssignableFrom<SigstoreException>(ex);
    }

    [Fact]
    public void FulcioException_PreservesMessage()
    {
        var ex = new FulcioException("Fulcio CSR rejected");
        Assert.Equal("Fulcio CSR rejected", ex.Message);
    }

    [Fact]
    public void FulcioException_PreservesInnerException()
    {
        var inner = new HttpRequestException("inner");
        var ex = new FulcioException("outer", inner);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void RekorException_IsSubclassOfSigstoreException()
    {
        var ex = new RekorException("test");
        Assert.IsAssignableFrom<SigstoreException>(ex);
    }

    [Fact]
    public void RekorException_PreservesMessage()
    {
        var ex = new RekorException("Rekor rejected entry");
        Assert.Equal("Rekor rejected entry", ex.Message);
    }

    [Fact]
    public void RekorException_PreservesInnerException()
    {
        var inner = new InvalidOperationException("inner");
        var ex = new RekorException("outer", inner);
        Assert.Same(inner, ex.InnerException);
    }

    [Fact]
    public void SigningException_IsSubclassOfSigstoreException()
    {
        var ex = new SigningException("test");
        Assert.IsAssignableFrom<SigstoreException>(ex);
    }

    [Fact]
    public void SigningException_PreservesMessage()
    {
        var ex = new SigningException("Signing orchestration failed");
        Assert.Equal("Signing orchestration failed", ex.Message);
    }

    [Fact]
    public void SigningException_PreservesInnerException()
    {
        var inner = new InvalidOperationException("inner");
        var ex = new SigningException("outer", inner);
        Assert.Same(inner, ex.InnerException);
    }
}
