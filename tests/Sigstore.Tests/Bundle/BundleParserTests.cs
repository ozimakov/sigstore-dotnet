using Sigstore.Bundle;
using Sigstore.Exceptions;

namespace Sigstore.Tests.Bundle;

public sealed class BundleParserTests
{
    [Fact]
    public void Given_InvalidJson_When_Parse_Then_ThrowsBundleParseException()
    {
        BundleParser parser = new BundleParser();
        Assert.Throws<BundleParseException>(() => parser.Parse("{not-json"));
    }
}
