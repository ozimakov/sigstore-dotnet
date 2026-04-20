# Verification

## Policies

`VerificationPolicy` supports:

- **Exact issuer + exact identity** — `VerificationPolicy.ForExact(issuer, identity)`
- **Exact issuer + regex identity** — `VerificationPolicy.ForRegexSubject(issuer, pattern)`
- **GitHub Actions** — `VerificationPolicy.ForGitHubActions(repository, gitRef, workflow?)` targeting `https://token.actions.githubusercontent.com`

Identity material is taken from Fulcio X.509 extensions (`1.3.6.1.4.1.57264.1.8` issuer, `1.3.6.1.4.1.57264.1.24` token subject when present) and Subject Alternative Name URIs.

## Trusted root

By default the library fetches and verifies the Public Good trusted root via TUF. For tests or air-gapped environments you can pass trusted root JSON directly to `Verifier.VerifyAsync(..., trustedRootJson: File.ReadAllText("trusted_root.json"), ...)`.

## Artifacts

v0.1 expects **local artifact bytes** for signature verification. Digest-only inputs (`sha256:...`) are not supported yet; pass a file path as described in the conformance CLI protocol.

## Failure modes

Failures use typed exceptions (`BundleParseException`, `TrustedRootException`, `CertificateValidationException`, `IdentityPolicyException`, `TransparencyLogException`, `InclusionProofException`, `SignatureVerificationException`) with messages that name the failing step.
