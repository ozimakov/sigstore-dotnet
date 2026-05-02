---
title: Cosign Integration — sign with cosign, verify with .NET
description: Use cosign to sign container images and artifacts, then verify those bundles with sigstore-dotnet. Bundles are fully interoperable across clients.
---

# Cosign Integration

Like [sigstore-java](https://github.com/sigstore/sigstore-java) and [sigstore-python](https://github.com/sigstore/sigstore-python), sigstore-dotnet focuses on **artifact signing and verification**. Container image signing is handled by [cosign](https://github.com/sigstore/cosign) — the bundles are fully interoperable.

## Sign with cosign, verify with .NET

```bash
# Sign a container image and save the bundle
cosign sign-blob --yes --bundle bundle.sigstore.json --new-bundle-format artifact.tar.gz

# Verify the bundle with sigstore-dotnet
dotnet-sigstore verify-bundle \
  --bundle bundle.sigstore.json \
  --certificate-identity "..." \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  artifact.tar.gz
```

## Sign with .NET, verify with cosign

```bash
# Sign with sigstore-dotnet
dotnet-sigstore sign-bundle \
  --identity-token "$TOKEN" \
  --bundle artifact.sigstore.json \
  artifact.tar.gz

# Verify with cosign
cosign verify-blob \
  --bundle artifact.sigstore.json \
  --new-bundle-format \
  --certificate-identity "..." \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  artifact.tar.gz
```

## Interop guarantee

Cross-client compatibility is verified on every push by [interop tests](https://github.com/ozimakov/sigstore-dotnet/actions/workflows/interop.yml) that sign and verify across cosign, sigstore-python, and sigstore-dotnet in both directions.
