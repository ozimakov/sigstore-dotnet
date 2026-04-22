# v0.3 Design: Verification Completeness

**Date:** 2026-04-22
**Goal:** Clear all conformance xfails. Zero failures, zero xfails (verification only; signing conformance is phase 2).

## Scope

### 1. BouncyCastle Ed25519

Add `Portable.BouncyCastle` package reference to `Sigstore.csproj`. Implement Ed25519 signature verification in `SignedNoteVerifier` using BC's `Ed25519PublicKeyParameters` + `Ed25519Signer.VerifySignature`. Remove the `#if NET10_0_OR_GREATER` conditional and the "Ed25519 not supported" fallback. Update `architecture.md` and any "BCL-only" or "no BouncyCastle" language across the repo to reflect the actual dependency policy: "pure managed .NET — no native/P-Invoke crypto."

### 2. Managed-key verification

Internal branching in `VerificationPipeline`: when the bundle's `VerificationMaterial` contains a `PublicKeyIdentifier` instead of an X.509 certificate chain, resolve the public key from the `TrustedRoot`, skip Fulcio chain validation (step 3) and identity policy (step 4), and verify the artifact signature directly against the resolved key.

Conformance runner changes: parse `--key <path>`, load the PEM public key, build a minimal `TrustedRoot` containing it, and call the existing `VerifyAsync` without identity/issuer requirements.

### 3. Digest input mode

`ConformanceRunner.LoadArtifactOrDigestAsync`: parse `sha256:<hex>` inputs into a 32-byte digest instead of throwing. Pass through to `VerifyAsync`.

`VerificationPipeline`: when verifying a `message_signature` bundle with a pre-computed digest (not raw artifact bytes), compare directly against `messageSignature.messageDigest` without re-hashing.

### 4. Negative validations

Eight guard checks across the pipeline:

| Check | Location | Behavior |
|-------|----------|----------|
| Bundle media type recognized | `BundleParser.Parse` | Reject unknown `mediaType` values |
| `logIndex >= 0` | `VerificationPipeline.ExtractTransparencyLogEntry` | Throw if negative |
| `integratedTime <= now + 5min` | `ValidateCertificateTiming` | Reject future timestamps |
| Artifact digest matches bundle | `VerifyHashedMessageSignature` | Compare input digest vs `messageDigest` |
| Checkpoint root hash matches proof | `TransparencyLogVerifier` | Parse checkpoint body, compare `rootHash` |
| Key hint matches log key | `SignedNoteVerifier` | Validate 4-byte hint against SHA-256(SPKI)[:4] |
| `canonicalizedBody` cross-check | `TransparencyLogVerifier` | Decode body, verify cert/sig/digest match bundle |
| SCT key in trusted root | `VerificationPipeline` | If SCT present, verify CT log key exists in trusted root |

### 5. In-toto investigation

After workstreams 1-4 land, investigate whether intoto conformance tests pass. If they fail due to missing in-toto statement validation, implement payload type and subject matching. If they fail due to key type (Ed25519), they should already be fixed by workstream 1.

### 6. CPython bundles

Re-enable `skip-cpython-release-tests: false` in the conformance workflow. Should pass automatically once Ed25519 verification works.

### 7. Documentation update

Replace "BCL-only crypto" / "no BouncyCastle" language with accurate description: "pure managed .NET — no native or P/Invoke cryptographic dependencies." Update `architecture.md`, `README.md`, package descriptions, and any XML doc comments.

## Non-goals

- sign-bundle in conformance runner (phase 2, immediately after v0.3)
- KMS integrations
- OCI image verification

## Dependency graph

```
BouncyCastle (1) ──► Ed25519 checkpoint passes ──► CPython passes (6)
Managed-key (2) ─┐
Digest mode (3) ─┤► DIGEST-* variants pass
                 │
Negative vals (4) ──► _fail tests pass
In-toto (5) ──► investigate after 1-4
Documentation (7) ──► after BouncyCastle added
```

## Testing strategy

- Each workstream: TDD — write failing test, implement, pass, commit
- Final gate: conformance suite with **empty xfail list**, `skip-signing: true`, `skip-cpython-release-tests: false`, **0 failures**
