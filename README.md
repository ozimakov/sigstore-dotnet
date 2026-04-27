# sigstore-dotnet

Managed .NET client library for [Sigstore](https://www.sigstore.dev/) bundle signing and verification. Uses `System.Security.Cryptography` + [BouncyCastle](https://www.bouncycastle.org/csharp/) for Ed25519 — no native binaries, no `unsafe` code. Targets .NET 8, 9, and 10.

[![NuGet](https://img.shields.io/nuget/v/Sigstore.Net?label=NuGet&color=004880)](https://www.nuget.org/packages/Sigstore.Net)
[![CI](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/ci.yml)
[![Conformance](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/conformance.yml/badge.svg)](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/conformance.yml)
[![Interop](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/interop.yml/badge.svg)](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/interop.yml)
[![codecov](https://codecov.io/gh/ozimakov/sigstore-dotnet/graph/badge.svg)](https://codecov.io/gh/ozimakov/sigstore-dotnet)
[![License](https://img.shields.io/github/license/ozimakov/sigstore-dotnet)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8%20%7C%209%20%7C%2010-512BD4)](https://dotnet.microsoft.com)

> **Status: alpha (v0.9).** The public API may change before v1.0.

## What is Sigstore?

[Sigstore](https://www.sigstore.dev/) is an open-source project that makes software supply-chain signing and verification transparent, auditable, and accessible. Artifacts are signed with short-lived X.509 certificates issued by [Fulcio](https://github.com/sigstore/fulcio) — tied to an OIDC identity from GitHub Actions, Google, or Microsoft — and every signing event is recorded in the [Rekor](https://github.com/sigstore/rekor) transparency log, eliminating the need to manage long-lived private keys.

## Features

| Feature | Status |
|---------|--------|
| **Bundle verification** — keyless (Fulcio + Rekor) | Supported |
| **Bundle verification** — managed public key | Supported |
| **Bundle signing** — keyless (OIDC + Fulcio + Rekor) | Supported |
| **Bundle formats** — `message_signature` and DSSE | Supported |
| **In-toto attestation** verification | Supported |
| **Digest-only** verification (`sha256:<hex>`) | Supported |
| **Ed25519** signatures (via BouncyCastle) | Supported |
| **ECDSA P-256** and **RSA** signatures | Supported |
| **TUF trust bootstrap** against the Public Good Instance | Supported |
| **RFC 3161 timestamps** and Rekor integrated time | Supported |
| **Dependency injection** — `AddSigstore()` / `AddSigstoreSigning()` | Supported |
| **OIDC token providers** — GitHub Actions, env var, ambient | Supported |
| **Rekor2** bundles (TSA timestamps, Ed25519 checkpoints) | Supported |
| **SCT validation** and **SET verification** | Supported |
| **Signing config** — custom Fulcio/Rekor/TSA endpoints | Supported |
| Conformance test suite (3x matrix: net8/9/10) | **132 passed, 0 xfailed** |
| OCI image verification | Planned |
| KMS integrations | Planned |

## Installation

```
dotnet add package Sigstore.Net
```

## Quickstart — verification

### With dependency injection (recommended)

```csharp
// Program.cs
builder.Services.AddSigstore();
```

```csharp
public class MyService(Verifier verifier)
{
    public async Task VerifyAsync(string bundleJson, byte[] artifact)
    {
        VerificationPolicy policy = VerificationPolicy.ForGitHubActions(
            issuer: "https://token.actions.githubusercontent.com",
            repository: "my-org/my-repo");

        VerificationResult result = await verifier.VerifyAsync(
            bundleJson, artifact, policy, CancellationToken.None);

        Console.WriteLine($"Verified. Signed by: {result.Identity.Subject}");
    }
}
```

### Managed-key verification

Verify bundles signed with a standalone public key (no Fulcio certificate):

```csharp
string publicKeyPem = await File.ReadAllTextAsync("cosign.pub");

VerificationResult result = await verifier.VerifyWithKeyAsync(
    bundleJson, artifact, publicKeyPem,
    trustedRootJson: trustedRoot,
    CancellationToken.None);
```

### Without dependency injection

```csharp
using Microsoft.Extensions.Logging.Abstractions;
using Sigstore.Bundle;
using Sigstore.Crypto;
using Sigstore.Fulcio;
using Sigstore.Rekor;
using Sigstore.Time;
using Sigstore.Tuf;
using Sigstore.Verification;

using HttpClient http = new();
Verifier verifier = new(
    new VerificationPipeline(
        new BundleParser(),
        new CertificateVerifier(),
        new TransparencyLogVerifier(),
        new SignatureVerifier(),
        new DefaultSystemClock(),
        NullLogger<VerificationPipeline>.Instance),
    new TufClient(http, NullLogger<TufClient>.Instance),
    NullLogger<Verifier>.Instance);

string bundleJson = await File.ReadAllTextAsync("artifact.sigstore.json");
byte[] artifact = await File.ReadAllBytesAsync("artifact.tar.gz");

VerificationPolicy policy = VerificationPolicy.ForExact(
    issuer: "https://token.actions.githubusercontent.com",
    subject: "repo:my-org/my-repo:ref:refs/heads/main");

VerificationResult result = await verifier.VerifyAsync(
    bundleJson, artifact, policy, CancellationToken.None);
```

## Quickstart — signing

### With dependency injection

```csharp
builder.Services.AddSigstoreSigning(options =>
{
    options.TokenProvider = new StaticTokenProvider(myOidcToken);
});
```

```csharp
public class MyService(Signer signer)
{
    public async Task SignAsync(byte[] artifact)
    {
        SigningResult result = await signer.SignAsync(artifact, CancellationToken.None);
        await File.WriteAllTextAsync("artifact.sigstore.json", result.BundleJson);
        Console.WriteLine($"Signed by: {result.Identity.Subject}");
    }
}
```

### OIDC token providers

| Provider | Source | Use case |
|----------|--------|----------|
| `GitHubActionsTokenProvider` | GHA OIDC federation | CI/CD pipelines |
| `EnvVarTokenProvider` | `SIGSTORE_ID_TOKEN` env var | Local dev, scripts |
| `AmbientTokenProvider` | Auto-detects GHA or env var | General purpose |
| `StaticTokenProvider` | Caller-provided token string | Tests, custom flows |

## Verification policies

| Method | Matches | Typical use case |
|--------|---------|-----------------|
| `VerificationPolicy.ForExact(issuer, subject)` | Exact OIDC issuer **and** subject string | Service account email, specific workflow ref |
| `VerificationPolicy.ForRegexSubject(issuer, pattern)` | Exact issuer, regex on subject | Wildcard across branches or repos |
| `VerificationPolicy.ForGitHubActions(issuer, repository)` | GitHub Actions token for a specific repo | CI/CD artifact provenance |

## Trusted root

By default the library fetches `trusted_root.json` from the [Sigstore TUF repository](https://tuf-repo-cdn.sigstore.dev) on the first call — the authoritative source for Fulcio CA certificates, Rekor public keys, and CT log information.

For **air-gapped** environments or tests, supply a trusted root directly:

```csharp
string trustedRootJson = await File.ReadAllTextAsync("trusted_root.json");

VerificationResult result = await verifier.VerifyAsync(
    bundleJson, artifact, policy,
    trustedRootJson: trustedRootJson,
    CancellationToken.None);
```

## Dependency injection

```csharp
// Verification only
services.AddSigstore();

// Verification + signing
services.AddSigstoreSigning(options =>
{
    options.FulcioUrl = new Uri("https://fulcio.sigstore.dev/");
    options.RekorUrl = new Uri("https://rekor.sigstore.dev/");
    options.OidcAudience = "sigstore";
    options.TokenProvider = new AmbientTokenProvider(httpClient);
    options.HttpTimeout = TimeSpan.FromSeconds(30);
});
```

## Conformance

`sigstore-dotnet` is tested against the official [sigstore-conformance](https://github.com/sigstore/sigstore-conformance) v0.0.25 test suite. Tests run as a 3x matrix across .NET 8, 9, and 10 on every push and weekly.

| Test category | Status |
|---------------|--------|
| Artifact verification — `message_signature` | Pass |
| Artifact verification — DSSE envelope | Pass |
| In-toto attestation verification | Pass |
| Bundle v0.3 format | Pass |
| Managed-key verification | Pass |
| Ed25519 (rekor2) verification | Pass |
| Digest-only verification | Pass |
| Negative validation tests | Pass (all verification xfails cleared) |
| TSA timestamp validation | Pass (message imprint, cert chain, authority/cert validity) |
| SCT / CT log validation | Pass |
| SET (Signed Entry Timestamp) verification | Pass |
| canonicalizedBody cross-check | Pass (hashedrekord, dsse 0.0.1/0.0.2, intoto 0.0.2) |
| Multi-signer checkpoints | Pass (C2SP key hints, Ed25519 + ECDSA) |

### Cross-client interop (15 tests)

Verified on every push against **cosign** and **sigstore-python**:

| Test | Direction |
|------|-----------|
| message_signature sign + verify | .NET ↔ Python (both directions) |
| DSSE in-toto attestation | Python → .NET |
| Digest-only verification | Both directions |
| cosign sign-blob → verify | cosign → .NET |
| .NET sign → cosign verify-blob | .NET → cosign |
| Tampered signature rejection | Both clients × both directions |
| Wrong issuer/identity rejection | Both clients × both directions |

## Container image signing (OCI)

Like [sigstore-java](https://github.com/sigstore/sigstore-java) and [sigstore-python](https://github.com/sigstore/sigstore-python), this library focuses on **artifact signing and verification**. For container image signing, use [cosign](https://github.com/sigstore/cosign) — the bundles are fully interoperable.

```bash
# Sign a container image with cosign, extract and verify the bundle with .NET
cosign sign --yes ghcr.io/my-org/my-image:latest
cosign save ghcr.io/my-org/my-image:latest --dir /tmp/image-bundle
# Verify the extracted bundle
dotnet-sigstore verify-bundle --bundle /tmp/image-bundle/bundle.sigstore.json ...

# Sign an artifact with .NET, attach to a container image with cosign
dotnet-sigstore sign-bundle --identity-token $TOKEN --bundle artifact.sigstore.json artifact.tar.gz
cosign attach signature --bundle artifact.sigstore.json ghcr.io/my-org/my-image:latest
```

## Architecture

The verification pipeline follows the [Sigstore client specification](https://github.com/sigstore/sigstore/blob/main/docs/client-spec.md):

1. Parse bundle JSON (protobuf JSON encoding) — reject unknown media types
2. Bootstrap trust via TUF — fetch and verify `trusted_root.json`
3. Build and verify Fulcio certificate chain against trusted CAs (or resolve managed key); validate SCT log IDs against trusted CT logs
4. Enforce identity policy (issuer + subject) — skipped for managed-key bundles
5. Validate certificate validity window against Rekor integrated time and/or RFC 3161 timestamps; validate TSA certificate chains and authority validity windows
6. Verify Rekor inclusion proof (Merkle path + signed checkpoint with Ed25519/ECDSA); cross-check canonicalizedBody (hashedrekord, dsse, intoto)
7. Verify SET (signed entry timestamp) cryptographic signature
8. Verify artifact signature (ECDSA, RSA, Ed25519) using the leaf certificate or provided public key

The signing pipeline generates an ephemeral ECDSA P-256 key, obtains a short-lived Fulcio certificate via OIDC, signs the artifact, uploads a transparency log entry to Rekor, and returns a Sigstore bundle v0.3 JSON.

See [docs/architecture.md](docs/architecture.md) for a detailed walkthrough.

## Roadmap

| Version | Scope |
|---------|-------|
| **v0.1** | Bundle verification, TUF trust bootstrap, Fulcio chain, Rekor inclusion proof, RFC 3161 timestamps |
| **v0.2** | Keyless signing pipeline, OIDC token providers, DI extensions |
| **v0.3** | Ed25519 via BouncyCastle, managed-key verification, digest mode, in-toto attestations, negative validations |
| **v0.4** | Conformance signing against real Sigstore infrastructure, Fulcio v2 REST API, canonicalizedBody cross-check, bundle v0.3 leaf-only cert |
| **v0.5** | Full verification conformance — TSA validation, SCT/SET verification, multi-signer checkpoints, DSSE/intoto cross-checks (128 passed, 0 xfailed) |
| **v0.6** | Signing conformance — signing-config, TSA timestamps, inclusion proof parsing, hashedrekord v0.0.2 |
| **v0.7** | Full conformance — Rekor v2 API client, DER signatures, zero xfails (**132 passed, 0 xfailed**) |
| **v0.8** | Cross-client interop tests — 12 test cases: message_signature, DSSE, digest, tamper detection, identity policy |
| **v0.9** *(current)* | Cosign interop — 15 tests including cosign sign/verify, documented OCI workflow via cosign |
| **v1.0** | Stable public API, full Sigstore client spec conformance |

## Contributing

Contributions are welcome — bug reports, features, documentation improvements, and conformance coverage all appreciated. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

To report a security vulnerability, please use [GitHub's private advisory system](https://github.com/ozimakov/sigstore-dotnet/security/advisories/new) rather than opening a public issue. See [SECURITY.md](SECURITY.md) for the full policy.

## License

[Apache License 2.0](LICENSE)
