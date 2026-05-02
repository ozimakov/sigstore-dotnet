# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] — 2026-05-02

### Changed

- README cleanup so nuget.org displays the current text: removed the outdated "Status: v1.0 — stable" banner and the Codecov badge. Coverage tracking on codecov.io continues to run from CI; only the public banner is gone.
- Conformance workflow retries once on transient Sigstore Public Good infra failures (Fulcio/Rekor/TUF), so an upstream blip no longer paints the badge red.

## [1.0.2] — 2026-05-01

### Added

- 58 new unit tests covering exception types, Merkle inclusion proof edge cases, Fulcio response parsing (PEM and JSON wrappers, error paths), X.509 extension decoding (OctetString-wrapped UTF-8, identity URI helpers), and trusted-root JSON parsing. Overall line coverage rose from ~50% to ~54%.

### Fixed

- `TrustedRootLoader.Parse` now wraps malformed-JSON errors (`InvalidJsonException`) in `TrustedRootException` so callers see the same exception type for both syntactic and semantic parse failures.

### Changed

- Package description now states the multi-target framework support explicitly (.NET 8, 9, and 10).
- `PackageTags` expanded with `keyless`, `fulcio`, `rekor`, `cosign`, `dsse`, `in-toto`, `net8`, `net9`, `net10` for better discoverability on nuget.org.

## [1.0.1] — 2026-05-01

### Changed

- `PackageProjectUrl` now points at the documentation site (`https://sigstore.zimakov.net`) instead of the GitHub repository. The repository link remains available on nuget.org via `RepositoryUrl`.

## [1.0.0] — 2026-04-27

### Added

- **Batch signing** — `SignBatchAsync` signs multiple artifacts with a single OIDC token and Fulcio certificate, amortizing auth overhead
- **Staging environment preset** — `SigstoreSigningOptions.Staging()` pre-configured for sigstage.dev
- **Codecov integration** — code coverage badge, protobuf-generated code excluded from metrics
- **GitHub Pages documentation site** — DocFX-generated API reference and articles, auto-deployed on every push
- **Cosign interop tests** — 15 cross-client tests (cosign + sigstore-python + .NET)
- 6 new unit tests: DSSE PAE encoding, VerificationPolicy factories

### Fixed

- README `ForGitHubActions` example now matches actual API signature (`repository`, `gitRef`)
- Removed unnecessary `Task.Yield()` from verification pipeline
- Fixed redundant `logIndex` parsing in Rekor v2 response handler
- Added XML doc to `SigningPipeline.RunAsync` TSA overload
- Updated NuGet package description for accuracy

### Changed

- Package version: **1.0.0** — stable public API
- 67 unit tests, 132 conformance tests, 15 interop tests across .NET 8, 9, and 10

## [0.9.0] — 2026-04-26

### Added

- **Cosign interop tests** — sign with cosign `sign-blob --new-bundle-format` and verify with .NET; sign with .NET and verify with cosign `verify-blob`; digest-mode cross-verification. Total: 15 interop test cases across cosign, sigstore-python, and .NET.
- **OCI / container image documentation** — following the sigstore-java and sigstore-python model, OCI container image signing is handled by cosign; documented the cosign integration workflow in the README with examples

## [0.8.1] — 2026-04-26

### Added

- **Expanded interop test matrix** — 12 cross-client test cases covering `message_signature`, DSSE in-toto attestation, digest-only verification, tampered signature rejection, and wrong identity/issuer rejection

## [0.8.0] — 2026-04-26

### Added

- **Cross-client interop tests** — new CI workflow (`interop.yml`) that signs with .NET and verifies with sigstore-python, and vice versa; covers `message_signature` and digest-only modes
- Interop badge in README

## [0.7.0] — 2026-04-26

### Added

- **Rekor v2 API client** — POST to `/api/v2/log/entries` with `hashedRekordRequestV002` JSON schema; DER-encoded certificate and base64 digest in the request body
- **Protobuf JSON response parsing** — use `Google.Protobuf.JsonParser` for Rekor v2 responses, correctly handling `canonicalizedBody` bytes, string-typed int64 fields, and nested protobuf objects
- **Dual-format response parser** — automatically detect and parse both v1 (hex hashes, UUID-wrapped JSON) and v2 (base64 hashes, direct protobuf JSON) Rekor response formats

### Fixed

- **DER-encoded ECDSA signatures** — explicitly use `DSASignatureFormat.Rfc3279DerSequence` per the Sigstore spec; .NET defaults to IEEE P1363 on some platforms, which caused cross-client verification failures

### Changed

- Conformance: **132 passed, 0 xfailed** — full conformance with zero xfails across all tests

## [0.6.0] — 2026-04-25

### Added

- **Signing config support** — `--signing-config` and `--trusted-root` CLI arguments for the `sign-bundle` command; extract Fulcio, Rekor, and TSA URLs from the SigningConfig protobuf
- **TSA timestamp requesting** — when a TSA URL is configured, request an RFC 3161 timestamp over the bundle signature and include it in `timestampVerificationData`
- **Inclusion proof parsing from Rekor** — parse `inclusionProof` (logIndex, treeSize, rootHash, hashes, checkpoint) from the Rekor v1 API response
- **hashedrekord v0.0.2 support** — select hashedrekord version based on signing config `majorApiVersion`; parse actual kind/version from Rekor response body
- **Rekor v2 API client** — POST to `/api/v2/log/entries` with `hashedRekordRequestV002` JSON schema; parse protobuf-style JSON responses with string-typed integers, base64 hashes, and nested objects

### Changed

- Rekor SET (inclusionPromise) and `integratedTime` are now optional — Rekor v2 uses TSA timestamps instead
- Rekor response parser handles both v1 (hex hashes, `{"uuid": {...}}` wrapper) and v2 (base64 hashes, direct entry object) formats
- Signing conformance re-enabled — `test_simple` and `test_sign_does_not_produce_root` pass
- Conformance: **131 passed, 1 xfailed** (`test_sign_verify_rekor2` — bundle format interop with sigstore-python selftest)

## [0.5.0] — 2026-04-25

### Added

- **TSA timestamp validation** — verify RFC 3161 message imprint matches bundle signature, validate TSA certificate chain against trusted root timestamp authorities, enforce TSA authority and certificate validity windows
- **SCT validation** — verify that SCT log IDs in the leaf certificate match a trusted CT log in the trusted root
- **SET (Signed Entry Timestamp) verification** — cryptographically verify the SET signature against the Rekor public key using the canonical entry payload
- **DSSE/intoto canonicalizedBody cross-check** — verify signatures in tlog entries for `dsse` v0.0.1/v0.0.2 and `intoto` v0.0.2 entry types (in addition to existing `hashedrekord` support)
- **Multi-signer checkpoint support** — iterate all signature lines in signed note checkpoints; support C2SP key hint format for Ed25519 keys
- **Inclusion proof requirement** — bundle v0.2+ requires an inclusion proof (inclusion promise alone is insufficient)

### Fixed

- **DIGEST mode for DSSE/in-toto** — pre-computed digests (`sha256:<hex>`) now correctly match against in-toto statement subjects without re-hashing
- **Managed-key wrong key in DIGEST mode** — detect invalid/unsupported keys upfront instead of silently accepting digest-only verification
- **Strict key hint validation** — reject checkpoint signatures with key hints that don't match any trusted log key
- **intoto double-base64 signatures** — correctly decode double-base64-encoded signatures in intoto v0.0.2 tlog entries

### Changed

- Conformance verification tests: **128 passed, 0 xfailed** (was 104 passed, 28 xfailed)
- Signing conformance tests skipped pending staging/signing-config support
- Conformance workflow: added `timeout-minutes: 15` to prevent runaway jobs from OIDC beacon downtime

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

[Unreleased]: https://github.com/ozimakov/sigstore-dotnet/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.9.0...v1.0.0
[0.9.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ozimakov/sigstore-dotnet/releases/tag/v0.1.0
