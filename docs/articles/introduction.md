---
title: Introduction to Sigstore — keyless signing for .NET
description: What Sigstore is, why it exists, and why a pure managed .NET implementation matters. Covers Fulcio, Rekor, TUF, and the supply-chain problem keyless signing solves.
---

# Introduction to Sigstore

## The supply chain problem

Every modern application depends on hundreds of upstream packages: NuGet packages, container base images, build artifacts, attestations from CI systems. A compromise anywhere in that chain — a stolen credential, a malicious dependency, a tampered release — can flow into production unnoticed.

Traditional code signing was the textbook answer: sign artifacts with a private key, distribute the public key out of band, verify on download. In practice it has gone unused in most ecosystems because:

- **Key management is hard.** Long-lived signing keys must be stored, rotated, revoked. Most teams skip the ceremony.
- **Distribution is hard.** Publishing public keys, building chains of trust, dealing with revocation lists — non-trivial work for every project.
- **Identity is missing.** A signature proves *someone* signed; it usually doesn't tell you *who* in a way you can verify.

[Sigstore](https://www.sigstore.dev/) is a Linux Foundation project that fixes these. Its model:

- **Keyless signing.** Generate an ephemeral key pair right before signing. Use it once. Throw it away.
- **OIDC-bound certificates.** Prove your identity (GitHub Actions, Google, Microsoft, etc.) to a CA called [Fulcio](https://github.com/sigstore/fulcio), which issues a short-lived X.509 certificate binding your OIDC subject to the ephemeral public key.
- **Tamper-evident transparency log.** Every signing event is recorded in a public Merkle log called [Rekor](https://github.com/sigstore/rekor). Anyone can audit. Tampering is detectable.
- **Trust roots distributed via TUF.** The set of trusted Fulcio CAs, Rekor keys, and CT log keys is published through [TUF](https://theupdateframework.io/) so clients can bootstrap trust without hard-coding anything.

The result: signing becomes a CI step that costs nothing, identities are real and verifiable, and any verifier can check a signature against the public infrastructure without operating their own PKI.

## Why a managed .NET implementation

The Sigstore project ships first-class clients for [Go](https://github.com/sigstore/sigstore-go), [Java](https://github.com/sigstore/sigstore-java), and [Python](https://github.com/sigstore/sigstore-python). Container image signing is handled by [cosign](https://github.com/sigstore/cosign). For .NET, the historical options were:

- **Shell out to cosign.** Works but adds an external binary dependency, complicates packaging, and leaves the .NET process dependent on a Go toolchain at runtime.
- **Use sigstore-go via P/Invoke.** Heavy, platform-specific, hard to audit, fights .NET's deployment story.
- **Reimplement in .NET.** What this library does.

`sigstore-dotnet` is a pure managed implementation that:

- Runs **everywhere .NET 8 / 9 / 10 runs** — Windows, Linux, macOS, ARM64, container, AOT-compatible.
- Has **no native binaries**. Cryptography is `System.Security.Cryptography` plus [BouncyCastle.Cryptography](https://www.bouncycastle.org/csharp/) for Ed25519. No P/Invoke, no `unsafe`.
- Plays naturally with **idiomatic .NET**: `Task<T>` / `async` everywhere, dependency injection via `Microsoft.Extensions.DependencyInjection`, configurable through `IOptions<T>`, logging via `Microsoft.Extensions.Logging.Abstractions`.
- Is **cross-client interoperable**. Bundles produced by sigstore-dotnet verify cleanly with [cosign](https://github.com/sigstore/cosign) and [sigstore-python](https://github.com/sigstore/sigstore-python), and vice versa. This is checked on every push by an [interop workflow](https://github.com/ozimakov/sigstore-dotnet/blob/main/.github/workflows/interop.yml).
- Passes the **full** [sigstore-conformance](https://github.com/sigstore/sigstore-conformance) test suite — 132 tests, zero xfails — across all three target frameworks.

## How it works

A signing operation runs through these steps:

1. **Obtain an OIDC identity token.** The library ships providers for ambient detection on GitHub Actions, an explicit `SIGSTORE_ID_TOKEN` env var, or any custom `IOidcTokenProvider`.
2. **Generate an ephemeral ECDSA P-256 keypair.**
3. **Build a CSR** binding the ephemeral public key.
4. **Submit the CSR + identity token to Fulcio.** Fulcio verifies the OIDC token, and issues a short-lived (typically 10-minute) X.509 certificate whose Subject Alternative Name carries the OIDC subject. The certificate is logged to a [Certificate Transparency log](https://certificate.transparency.dev/), producing an SCT.
5. **Sign the artifact** (or its DSSE pre-authentication encoding for in-toto attestations).
6. **Submit the entry to Rekor.** Rekor returns a transparency log entry with an inclusion proof and a Signed Entry Timestamp (SET).
7. **Optionally request an RFC 3161 timestamp** from a Timestamp Authority, when configured.
8. **Assemble a Sigstore protobuf bundle** carrying the certificate, signature, log entry, and any timestamps.

A verification operation runs the inverse pipeline. See the [Architecture](architecture.md) article for the full step-by-step flow with the typed exception that each step throws on failure.

### Bundle formats

The library reads and writes the [Sigstore bundle format](https://docs.sigstore.dev/about/bundle/) v0.1, v0.2, and v0.3. Both `MessageSignature` and DSSE envelope payloads are supported. In-toto statements carried inside DSSE envelopes are validated against the artifact digest using the standard subject-list scheme.

### Trust model

Trusted Fulcio CAs, Rekor keys, CT log keys, and Timestamp Authority chains are loaded from a `TrustedRoot` JSON document. By default, the library bootstraps this from the Sigstore Public Good Instance's [TUF repository](https://tuf-repo-cdn.sigstore.dev/) on first use. For air-gapped environments, custom trusted roots can be supplied directly. A staging preset (`SigstoreSigningOptions.Staging()`) is included for testing against the [Sigstore staging environment](https://docs.sigstore.dev/system_config/staging/).

## Conformance and interop testing

Cryptographic libraries are easy to write and hard to write *correctly*. sigstore-dotnet treats correctness as a first-class concern:

- **Conformance.** [sigstore-conformance v0.0.25](https://github.com/sigstore/sigstore-conformance) is the official cross-client test suite. The project's [Conformance workflow](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/conformance.yml) runs the suite on every push to `main` against .NET 8, 9, and 10. Current state: **132 passed, 0 xfailed**.
- **Interop.** A separate [Interop workflow](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/interop.yml) signs an artifact with sigstore-dotnet and verifies with [sigstore-python](https://github.com/sigstore/sigstore-python) and [cosign](https://github.com/sigstore/cosign), then signs with each of those clients and verifies with sigstore-dotnet. Both `message_signature` and DSSE in-toto attestations are exercised in both directions, plus negative cases (tampered signatures, wrong identity, wrong issuer). 15 cases total.
- **Unit tests.** 82 tests across the core types: bundle parsing, DSSE pre-authentication encoding, certificate identity matchers, signed-note parsing, signature algorithms (ECDSA, RSA, Ed25519), and the dependency injection extensions.

The whole thing builds and tests in under three minutes per framework.

## Where to next

- [Getting Started](getting-started.md) — install, set up DI, sign and verify your first artifact.
- [Cosign Integration](cosign-integration.md) — workflow for container image signatures via cosign.
- [Architecture](architecture.md) — the verification and signing pipelines step-by-step.
- [API Reference](xref:Sigstore.Verification.Verifier) — auto-generated from XML doc comments.

## Further reading

- [Sigstore project home](https://www.sigstore.dev/)
- [Sigstore client specification](https://github.com/sigstore/sigstore/blob/main/docs/client-spec.md)
- [Sigstore bundle format](https://docs.sigstore.dev/about/bundle/)
- [Fulcio — keyless signing CA](https://github.com/sigstore/fulcio)
- [Rekor — transparency log](https://github.com/sigstore/rekor)
- [TUF — The Update Framework](https://theupdateframework.io/)
- [in-toto attestation framework](https://in-toto.io/)
- [DSSE — Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- [SLSA — Supply-chain Levels for Software Artifacts](https://slsa.dev/)
