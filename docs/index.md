---
_layout: landing
---

# sigstore-dotnet

Managed .NET client library for [Sigstore](https://www.sigstore.dev/) bundle signing and verification — pure managed code, no native binaries, no `unsafe`. Targets .NET 8, 9, and 10.

## What is Sigstore?

[Sigstore](https://www.sigstore.dev/) is a Linux Foundation project for **keyless** software signing. Instead of managing long-lived private keys, signers prove their identity to an OIDC provider (GitHub Actions, Google, Microsoft, etc.) and receive a short-lived X.509 certificate from [Fulcio](https://github.com/sigstore/fulcio). Every signing event is recorded in [Rekor](https://github.com/sigstore/rekor), a public Merkle-tree transparency log. The trust roots are distributed via [TUF](https://theupdateframework.io/).

The result: signing becomes a free CI step, identities are real and verifiable, and any consumer can audit what was signed, by whom, and when — no private PKI required.

## Why a .NET implementation?

The Sigstore project ships first-class clients for Go, Java, and Python. For .NET, the historical options were to shell out to [cosign](https://github.com/sigstore/cosign) or P/Invoke into sigstore-go — both bring native dependencies and complicate deployment. `sigstore-dotnet` is a pure managed implementation that runs everywhere .NET runs, integrates with `Microsoft.Extensions.DependencyInjection` and `IOptions<T>`, and is fully cross-client interoperable with cosign and sigstore-python.

## Quick links

- [Introduction to Sigstore](articles/introduction.md) — concepts, architecture, why .NET
- [Getting Started](articles/getting-started.md) — install and first sign/verify
- [Cosign Integration](articles/cosign-integration.md) — container image workflow
- [Architecture](articles/architecture.md) — verification and signing pipelines
- [API Reference](xref:Sigstore.Verification.Verifier) — auto-generated from XML doc comments
- [Contributors](contributors.md) — everyone who has contributed
- [GitHub Repository](https://github.com/ozimakov/sigstore-dotnet)
- [NuGet Package](https://www.nuget.org/packages/Sigstore.Net)

## Verified

- **132/132** [sigstore-conformance](https://github.com/sigstore/sigstore-conformance) tests passing — zero xfails
- **15** cross-client [interop tests](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/interop.yml) (sign with cosign, verify with .NET, etc.)
- **82** unit tests across .NET 8, 9, and 10
