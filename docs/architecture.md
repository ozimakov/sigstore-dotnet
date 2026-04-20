# Architecture

## Verification pipeline (v0.1)

Verification is implemented as an ordered pipeline with typed failures at each step:

```
                    +----------------+
                    |  Bundle JSON   |
                    +--------+-------+
                             |
                             v
               +-------------+-------------+
               | 1. Parse bundle (proto) |
               +-------------+-------------+
                             |
                             v
               +-------------+-------------+
               | 2. Trusted root (TUF)   |
               +-------------+-------------+
                             |
                             v
               +-------------+-------------+
               | 3. Fulcio chain build   |
               +-------------+-------------+
                             |
                             v
               +-------------+-------------+
               | 4. Identity policy        |
               +-------------+-------------+
                             |
                             v
               +-------------+-------------+
               | 5. Validity window        |
               |    (Rekor time / RFC3161)|
               +-------------+-------------+
                             |
                             v
               +-------------+-------------+
               | 6. Rekor inclusion proof|
               |    + checkpoint / SET    |
               +-------------+-------------+
                             |
                             v
               +-------------+-------------+
               | 7. (implicit in 6)       |
               +-------------+-------------+
                             |
                             v
               +-------------+-------------+
               | 8. Artifact signature    |
               +-------------+-------------+
                             |
                             v
                    +--------+---------+
                    | VerificationResult |
                    +--------------------+
```

Steps map to exceptions rooted at `SigstoreException` (for example `TrustedRootException`, `InclusionProofException`).

## Pure managed cryptography

Enterprise .NET deployments often disallow native cryptographic libraries in security-sensitive components. This project uses **only** `System.Security.Cryptography` (including PKCS#7 / `SignedCms` where needed for RFC 3161 material) and does not depend on BouncyCastle or other third-party crypto.

## TUF trust bootstrap

The Public Good Instance trusted root is obtained from `tuf-repo-cdn.sigstore.dev` using a minimal TUF workflow:

1. Bootstrap from a pinned versioned `*.root.json` (updated as the upstream repository rotates roots).
2. Verify `timestamp.json`, `*.snapshot.json`, and `*.targets.json` signatures using keys from the trusted root metadata.
3. Download `trusted_root.json` from the `targets/` path referenced by the SHA-256 name in `targets.json`.

## Conformance runner

`Sigstore.Conformance` is packaged as a .NET global tool (`PackAsTool`) with command name `sigstore-dotnet`. It wires CLI flags to `Verifier` and is the binary exercised by `sigstore/sigstore-conformance`.

## Deferred (v0.2+)

- **Signing** (Fulcio, Rekor upload, bundle creation).
- **KMS** integrations and key management.
- **OCI** image verification helpers.
- **Benchmarks** and extended test vectors.
