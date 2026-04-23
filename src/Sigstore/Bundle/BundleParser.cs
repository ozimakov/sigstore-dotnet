using BundleProto = Dev.Sigstore.Bundle.V1.Bundle;
using Google.Protobuf;
using Sigstore.Exceptions;

namespace Sigstore.Bundle;

/// <summary>
/// Parses Sigstore bundle JSON using <see cref="Google.Protobuf.JsonParser"/>.
/// </summary>
public sealed class BundleParser : IBundleParser
{
    private readonly JsonParser _parser;

    /// <summary>
    /// Creates a parser with default settings (unknown fields ignored for forward compatibility).
    /// </summary>
    public BundleParser()
    {
        JsonParser.Settings settings = JsonParser.Settings.Default.WithIgnoreUnknownFields(true);
        _parser = new JsonParser(settings);
    }

    /// <inheritdoc />
    private static readonly HashSet<string> SupportedMediaTypes = new(StringComparer.Ordinal)
    {
        "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "application/vnd.dev.sigstore.bundle+json;version=0.2",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
        "application/vnd.dev.sigstore.bundle.v0.1+json",
        "application/vnd.dev.sigstore.bundle.v0.2+json",
        "application/vnd.dev.sigstore.bundle.v0.3+json",
    };

    public SigstoreBundle Parse(string json)
    {
        try
        {
            BundleProto bundle = _parser.Parse<BundleProto>(json);
            string mediaType = bundle.MediaType ?? string.Empty;

            if (!string.IsNullOrEmpty(mediaType) && !SupportedMediaTypes.Contains(mediaType))
            {
                throw new BundleParseException($"Step 1 (bundle parse): unsupported bundle media type '{mediaType}'.");
            }

            return new SigstoreBundle(mediaType, bundle);
        }
        catch (BundleParseException)
        {
            throw;
        }
        catch (Exception ex) when (ex is InvalidProtocolBufferException or Google.Protobuf.InvalidJsonException)
        {
            throw new BundleParseException("Step 1 (bundle parse): JSON is not a valid Sigstore bundle message.", ex);
        }
    }
}

/// <summary>
/// Parses Sigstore bundle JSON documents.
/// </summary>
public interface IBundleParser
{
    /// <summary>
    /// Parses a bundle JSON document.
    /// </summary>
    /// <param name="json">UTF-16 JSON text.</param>
    /// <returns>Parsed bundle view.</returns>
    SigstoreBundle Parse(string json);
}
