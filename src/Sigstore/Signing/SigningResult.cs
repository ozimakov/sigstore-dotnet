using Sigstore.Verification;

namespace Sigstore.Signing;

/// <summary>
/// Output of a successful signing operation.
/// </summary>
/// <param name="BundleJson">
/// Sigstore bundle v0.3 JSON, ready for use with <see cref="Verifier"/>.
/// The bundle contains an inclusion promise (SET), not a full Merkle inclusion proof.
/// </param>
/// <param name="Identity">The OIDC identity bound to the signing certificate.</param>
public sealed record SigningResult(string BundleJson, SignerIdentity Identity);
