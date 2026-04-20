# sigstore-dotnet

.NET client library for verifying [Sigstore](https://www.sigstore.dev/) bundles. Built entirely on `System.Security.Cryptography` — no BouncyCastle, no native binaries, no `unsafe` code. Targets .NET 8, 9, and 10.

[![NuGet](https://img.shields.io/nuget/v/Sigstore.Net?label=NuGet&color=004880)](https://www.nuget.org/packages/Sigstore.Net)
[![CI](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/ci.yml)
[![Conformance](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/conformance.yml/badge.svg)](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/conformance.yml)
[![License](https://img.shields.io/github/license/ozimakov/sigstore-dotnet)](LICENSE)
[![.NET](https://img.shields.io/badge/.NET-8%20%7C%209%20%7C%2010-512BD4)](https://dotnet.microsoft.com)

> **Status: alpha (v0.1).** The public API may change before v1.0. Bundle verification is fully supported; signing is planned for v0.2.

## What is Sigstore?

[Sigstore](https://www.sigstore.dev/) is an open-source project that makes software supply-chain signing and verification transparent, auditable, and accessible. Artifacts are signed with short-lived X.509 certificates issued by [Fulcio](https://github.com/sigstore/fulcio) — tied to an OIDC identity from GitHub Actions, Google, or Microsoft — and every signing event is recorded in the [Rekor](https://github.com/sigstore/rekor) transparency log, eliminating the need to manage long-lived private keys.

## About this library

`sigstore-dotnet` is a .NET client for the [Sigstore Public Good Instance](https://docs.sigstore.dev/about/infrastructure/) and compatible deployments. It relies solely on in-box BCL APIs (`System.Security.Cryptography`, `System.Net.Http`), making it suitable for security-sensitive, regulated, and air-gapped environments where third-party or native cryptographic dependencies are restricted.

v0.1 implements bundle verification. Signing is planned for v0.2.

## Installation

```
dotnet add package Sigstore.Net
```

## Quickstart

### With dependency injection (recommended)

```csharp
// Program.cs
builder.Services.AddSigstore();
```

```csharp
// Inject Verifier wherever you need it
public class MyService(Verifier verifier)
{
    public async Task VerifyAsync(string bundleJson, byte[] artifact)
    {
        VerificationPolicy policy = VerificationPolicy.ForGitHubActions(
            issuer: "https://token.actions.githubusercontent.com",
            repository: "my-org/my-repo");

        VerificationResult result = await verifier.VerifyAsync(
            bundleJson,
            artifact,
            policy,
            CancellationToken.None);

        Console.WriteLine($"Verified. Signed by: {result.Identity.Subject}");
    }
}
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

## Verification policies

| Method | Matches | Typical use case |
|--------|---------|-----------------|
| `VerificationPolicy.ForExact(issuer, subject)` | Exact OIDC issuer **and** subject string | Service account email, specific workflow ref |
| `VerificationPolicy.ForRegexSubject(issuer, pattern)` | Exact issuer, regex on subject | Wildcard across branches or repos |
| `VerificationPolicy.ForGitHubActions(issuer, repository)` | GitHub Actions token for a specific repo | CI/CD artifact provenance |

See [docs/verification.md](docs/verification.md) for full details and failure modes.

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

`AddSigstore()` registers all verification services including an `HttpClient`-backed TUF client:

```csharp
services.AddSigstore(); // registers Verifier, VerificationPipeline, TufClient, and supporting services
```

Inject `Verifier` directly; all dependencies are resolved automatically.

## Conformance

`sigstore-dotnet` is tested against the official [sigstore-conformance](https://github.com/sigstore/sigstore-conformance) test suite. Tests run on a weekly schedule and on every manual trigger.

| Test category | Status |
|---------------|--------|
| Artifact verification — `message_signature` | ✅ Pass |
| Artifact verification — DSSE envelope | ✅ Pass |
| Bundle v0.3 format | ✅ Pass |
| in-toto attestations | ⏭ xfail (planned v0.2) |
| Managed key / KMS | ⏭ xfail (planned v0.3) |
| Bundle signing | ⏭ xfail (planned v0.2) |

The `Sigstore.Net.Conformance` package provides the CLI tool used by the conformance suite. It is published as a [.NET global tool](https://learn.microsoft.com/en-us/dotnet/core/tools/global-tools):

```
dotnet tool install --global Sigstore.Net.Conformance
```

## Architecture

The verification pipeline follows the [Sigstore client specification](https://github.com/sigstore/sigstore/blob/main/docs/client-spec.md):

1. Parse bundle JSON (protobuf JSON encoding)
2. Bootstrap trust via TUF — fetch and verify `trusted_root.json`
3. Build and verify Fulcio certificate chain against trusted CAs
4. Enforce identity policy (issuer + subject)
5. Validate certificate validity window against Rekor integrated time and RFC 3161 countersignatures
6. Verify Rekor inclusion proof (Merkle path + signed tree-head checkpoint)
7. Verify SET (signed entry timestamp) signature
8. Verify artifact signature using the leaf certificate public key

See [docs/architecture.md](docs/architecture.md) for a detailed walkthrough.

## Roadmap

| Version | Scope |
|---------|-------|
| **v0.1** *(current)* | Bundle verification, TUF trust bootstrap, Fulcio chain, Rekor inclusion proof, RFC 3161 timestamps |
| **v0.2** | Bundle signing, DSSE attestations, OCI registry bundles |
| **v0.3** | KMS / hardware key support, benchmarks, performance tuning |

## Contributing

Contributions are welcome — bug reports, features, documentation improvements, and conformance coverage all appreciated. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

To report a security vulnerability, please use [GitHub's private advisory system](https://github.com/ozimakov/sigstore-dotnet/security/advisories/new) rather than opening a public issue. See [SECURITY.md](SECURITY.md) for the full policy.

## License

[Apache License 2.0](LICENSE)
