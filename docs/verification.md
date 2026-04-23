# Verification

## Policies

`VerificationPolicy` supports:

- **Exact issuer + exact identity** — `VerificationPolicy.ForExact(issuer, identity)`
- **Exact issuer + regex identity** — `VerificationPolicy.ForRegexSubject(issuer, pattern)`
- **GitHub Actions** — `VerificationPolicy.ForGitHubActions(repository, gitRef, workflow?)` targeting `https://token.actions.githubusercontent.com`

Identity material is taken from Fulcio X.509 extensions (`1.3.6.1.4.1.57264.1.8` issuer, `1.3.6.1.4.1.57264.1.24` token subject when present), OtherName SAN entries (`1.3.6.1.4.1.57264.1.7` for GitHub Actions workflow URIs), and Subject Alternative Name URIs.

## Verification modes

### Keyless (Fulcio + Rekor)

The default mode. The bundle contains a Fulcio certificate chain. The verifier:
1. Builds and verifies the certificate chain against the trusted root
2. Enforces the identity policy (OIDC issuer + subject)
3. Validates the certificate's validity window against the Rekor integrated time or RFC 3161 timestamp
4. Verifies the Rekor inclusion proof and signed checkpoint
5. Verifies the artifact signature using the leaf certificate's public key

### Managed key

For bundles signed with a standalone public key (no Fulcio certificate). Use `VerifyWithKeyAsync`:

```csharp
VerificationResult result = await verifier.VerifyWithKeyAsync(
    bundleJson, artifact, publicKeyPem, trustedRootJson, cancellationToken);
```

This skips Fulcio chain validation (step 3) and identity policy enforcement (step 4), and verifies the artifact signature directly against the provided public key.

## Trusted root

By default the library fetches and verifies the Public Good trusted root via TUF. For tests or air-gapped environments you can pass trusted root JSON directly to `Verifier.VerifyAsync(..., trustedRootJson: File.ReadAllText("trusted_root.json"), ...)`.

## Artifacts

The verifier accepts:
- **Raw artifact bytes** — the full artifact content for signature verification
- **Pre-computed digests** — `sha256:<hex>` digest strings (32-byte SHA-256 hash). In digest mode, the signature cannot be verified against the original bytes, but the digest match plus tlog inclusion provides integrity assurance per the Sigstore client spec.

## Bundle content types

| Content type | Description |
|-------------|-------------|
| `message_signature` | SHA-256 digest + ECDSA/RSA/Ed25519 signature over the artifact |
| `dsseEnvelope` | DSSE (Dead Simple Signing Envelope) with in-toto statement payload |

For DSSE bundles with `application/vnd.in-toto+json` payload type, the verifier matches the artifact's SHA-256 digest against the in-toto statement's subject digests.

## Supported algorithms

| Algorithm | Key source | Support |
|-----------|-----------|---------|
| ECDSA P-256 (SHA-256) | BCL `System.Security.Cryptography` | Full |
| RSA (PSS + PKCS#1 v1.5) | BCL `System.Security.Cryptography` | Full |
| Ed25519 | BouncyCastle.Cryptography | Full |

## Failure modes

Failures use typed exceptions rooted at `SigstoreException`:

| Exception | Step | Description |
|-----------|------|-------------|
| `BundleParseException` | 1 | Invalid JSON, unsupported media type, missing fields, negative logIndex |
| `TrustedRootException` | 2 | TUF metadata fetch/verification failure |
| `CertificateValidationException` | 3, 5 | Chain build failure, timing validation (future integratedTime, expired cert window) |
| `IdentityPolicyException` | 4 | OIDC issuer or subject mismatch |
| `TransparencyLogException` | 6 | Inclusion proof failure, checkpoint mismatch, signed note verification failure |
| `SignatureVerificationException` | 8 | Artifact signature mismatch, unsupported algorithm, digest mismatch |
