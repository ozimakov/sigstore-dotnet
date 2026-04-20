# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ozimakov/sigstore-dotnet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ozimakov/sigstore-dotnet/releases/tag/v0.1.0
