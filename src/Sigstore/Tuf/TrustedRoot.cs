using Dev.Sigstore.Trustroot.V1;
using Google.Protobuf;
using Sigstore.Exceptions;

namespace Sigstore.Tuf;

/// <summary>
/// Loads <see cref="TrustedRoot"/> messages from the Sigstore protobuf JSON encoding.
/// </summary>
public static class TrustedRootLoader
{
    /// <summary>
    /// Parses trusted root JSON (media type <c>application/vnd.dev.sigstore.trustedroot+json;version=0.1</c> or later).
    /// </summary>
    /// <param name="json">UTF-16 JSON text.</param>
    /// <returns>Parsed trusted root.</returns>
    public static TrustedRoot Parse(string json)
    {
        try
        {
            JsonParser parser = new JsonParser(JsonParser.Settings.Default.WithIgnoreUnknownFields(true));
            return parser.Parse<TrustedRoot>(json);
        }
        catch (Exception ex) when (ex is InvalidProtocolBufferException or InvalidJsonException)
        {
            throw new TrustedRootException("Step 2 (trusted root): trusted root JSON could not be parsed.", ex);
        }
    }
}
