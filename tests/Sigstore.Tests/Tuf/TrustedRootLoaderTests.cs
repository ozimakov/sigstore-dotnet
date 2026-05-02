using Sigstore.Exceptions;
using Sigstore.Tuf;

namespace Sigstore.Tests.Tuf;

public sealed class TrustedRootLoaderTests
{
    [Fact]
    public void Parse_MinimalValidJson_ReturnsTrustedRoot()
    {
        // Empty trusted root with just the media type — protobuf JSON tolerates the absent collections.
        const string json = "{\"mediaType\":\"application/vnd.dev.sigstore.trustedroot+json;version=0.1\"}";

        var root = TrustedRootLoader.Parse(json);

        Assert.NotNull(root);
        Assert.Equal("application/vnd.dev.sigstore.trustedroot+json;version=0.1", root.MediaType);
    }

    [Fact]
    public void Parse_IgnoresUnknownFields()
    {
        const string json = "{\"mediaType\":\"application/vnd.dev.sigstore.trustedroot+json;version=0.1\",\"futureField\":42}";

        var root = TrustedRootLoader.Parse(json);

        Assert.NotNull(root);
    }

    [Fact]
    public void Parse_InvalidJson_ThrowsTrustedRootException()
    {
        Assert.Throws<TrustedRootException>(() => TrustedRootLoader.Parse("not even json"));
    }

    [Fact]
    public void Parse_WrongShape_ThrowsTrustedRootException()
    {
        // tlogs expects an array but we pass a string — protobuf rejects the type mismatch.
        const string json = "{\"tlogs\":\"definitely-not-an-array\"}";

        Assert.Throws<TrustedRootException>(() => TrustedRootLoader.Parse(json));
    }
}
