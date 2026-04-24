# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] — 2026-04-24

### Added

- **Conformance signing** — `sign-bundle` command wired into the conformance CLI runner, exercised against real Sigstore infrastructure (Fulcio + Rekor)
- **canonicalizedBody cross-check** — verify tlog entry body matches the bundle's artifact hash and signature

### Fixed

- **Fulcio v2 REST API** — switched from defunct gRPC-JSON path to `/api/v2/signingCert` with Bearer auth and PEM response parsing
- **Fulcio PEM-in-JSON** — handle PEM-encoded certificates inside JSON `signedCertificateEmbeddedSct` response
- **Rekor publicKey encoding** — base64-encode PEM certificate for `publicKey.content` field
- **Bundle v0.3 format** — use single `certificate` field (leaf only) instead of `x509CertificateChain` (full chain) per spec
- **hashedrekord version** — use v0.0.1 (production Rekor)

### Changed

- Conformance signing tests enabled (`skip-signing` removed)

## [0.3.0] — 2026-04-23

### Added

- **Ed25519 signature verification** via BouncyCastle.Cryptography — supports Ed25519 signed-note checkpoints, artifact signatures, and DSSE envelopes
- **Managed-key verification** — `VerifyWithKeyAsync` for bundles signed with a standalone public key (no Fulcio certificate required)
- **Digest input mode** — verify bundles using `sha256:<hex>` pre-computed digests instead of raw artifact bytes
- **In-toto statement verification** — DSSE bundles with `application/vnd.in-toto+json` payload type now match artifact digest against statement subjects

### Fixed

- Bundle media type validation — reject unknown media types
- Negative `logIndex` rejection
- Future `integratedTime` rejection (>5 min skew)
- Checkpoint root hash and tree size cross-validated against inclusion proof
- DSSE envelope signature verification consolidated to use `SignatureVerifier` (eliminates duplicated ECDSA/RSA logic)

### Changed

- Conformance tests now run as a 3x matrix (net8.0, net9.0, net10.0)
- Crypto dependency policy updated: "managed .NET only — no native/P-Invoke crypto" (BouncyCastle is pure managed)

## [0.2.0] — 2026-04-21

### Added

- Keyless signing pipeline (`Signer`, `SigningPipeline`) — generates an ephemeral ECDSA P-256 key, obtains a short-lived Fulcio certificate via OIDC, signs the artifact, uploads a transparency log entry to Rekor, and returns a Sigstore bundle v0.3 JSON
- `message_signature` and DSSE signing via `Signer.SignAsync` / `Signer.SignDsseAsync`
- OIDC token providers: `GitHubActionsTokenProvider` (OIDC federation from GHA), `EnvVarTokenProvider` (`SIGSTORE_ID_TOKEN`), `AmbientTokenProvider` (auto-selects GHA → env-var), and `StaticTokenProvider` (tests / custom flows)
- `SigstoreSigningOptions` — configure Fulcio URL, Rekor URL, OIDC audience, token provider, and HTTP timeout
- `services.AddSigstoreSigning()` — one-call DI registration for the full signing + verification stack
- `TransparencyLogVerifier` now accepts bundles with an inclusion promise (SET) only, without a full Merkle inclusion proof, per the Sigstore client specification
- Signing exception types: `FulcioException`, `RekorException`, `OidcTokenException`

## [0.1.0] — 2026-04-19

### Added

- Bundle verification pipeline: Fulcio X.509 certificate chain, Rekor transparency log inclusion proof, and artifact signature verification
- TUF-based trust bootstrap against the Sigstore Public Good Instance (`tuf-repo-cdn.sigstore.dev`)
- Verification policies: `ForExact`, `ForRegexSubject`, and `ForGitHubActions`
- `message_signature` and DSSE (Dead Simple Signing Envelope) bundle content support
- RFC 3161 countersignature support for certificate validity window validation
- `services.AddSigstore()` dependency injection extension
- Multi-target support for .NET 8, 9, and 10
- `Sigstore.Net.Conformance` — CLI tool implementing the [sigstore-conformance](https://github.com/sigstore/sigstore-conformance) test protocol, published as a .NET global tool

[Unreleased]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ozimakov/sigstore-dotnet/releases/tag/v0.1.0
