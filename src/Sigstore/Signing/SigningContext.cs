using System.Security.Cryptography;

namespace Sigstore.Signing;

/// <summary>
/// Mutable context threaded through the signing pipeline. Never exposed publicly.
/// Only holds state that must survive across pipeline steps (the ephemeral key
/// for disposal in the finally block).
/// </summary>
internal sealed class SigningContext
{
    // Inputs
    public required byte[] Artifact { get; init; }

    /// <summary>null for message_signature; content-type for DSSE.</summary>
    public required string? PayloadType { get; init; }

    // Resolved during pipeline

    public ECDsa? EphemeralKey { get; set; }
}
