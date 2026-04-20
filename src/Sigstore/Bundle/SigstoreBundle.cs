using BundleProto = Dev.Sigstore.Bundle.V1.Bundle;

namespace Sigstore.Bundle;

/// <summary>
/// Strongly-typed view of a Sigstore bundle JSON document (protobuf JSON encoding).
/// </summary>
public sealed record SigstoreBundle
{
    /// <summary>
    /// Creates a bundle view.
    /// </summary>
    /// <param name="mediaType">Bundle media type string.</param>
    /// <param name="model">Underlying protobuf model.</param>
    public SigstoreBundle(string mediaType, BundleProto model)
    {
        MediaType = mediaType;
        Model = model;
    }

    /// <summary>
    /// Bundle media type (for example <c>application/vnd.dev.sigstore.bundle.v0.3+json</c>).
    /// </summary>
    public string MediaType { get; }

    /// <summary>
    /// Parsed protobuf bundle message.
    /// </summary>
    public BundleProto Model { get; }
}
