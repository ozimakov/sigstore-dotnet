# v0.4 Conformance Signing + Negative Validations

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove `skip-signing: true` and clear the entire xfail list. Target: 0 failures, 0 xfails across net8/9/10.

**Architecture:** Two parallel workstreams. WS-A wires the existing `SigningPipeline` into the conformance runner's `sign-bundle` command. WS-B adds missing negative validations to the verification pipeline so that all `_fail` conformance tests correctly reject invalid bundles.

**Tech Stack:** C#, .NET 8/9/10, xunit, sigstore-conformance v0.0.25

---

## Workstream A: Conformance Signing

### Task A1: Implement `RunSignAsync` in ConformanceRunner

**Files:**
- Modify: `src/Sigstore.Conformance/ConformanceRunner.cs`

- [ ] **Step 1: Implement `RunSignAsync`**

Replace the stub at line 32-36 with a call to `RunSignAsync`:

```csharp
if (string.Equals(command, "sign-bundle", StringComparison.OrdinalIgnoreCase))
{
    return await RunSignAsync(args.AsMemory(1)).ConfigureAwait(false);
}
```

Add the method:

```csharp
private static async Task<int> RunSignAsync(ReadOnlyMemory<string> args)
{
    string? identityToken = null;
    string? bundleOutputPath = null;
    string? artifactPath = null;

    for (int i = 0; i < args.Length; i++)
    {
        string a = args.Span[i];
        if (string.Equals(a, "--identity-token", StringComparison.Ordinal) && i + 1 < args.Length)
        {
            identityToken = args.Span[++i];
            continue;
        }

        if (string.Equals(a, "--bundle", StringComparison.Ordinal) && i + 1 < args.Length)
        {
            bundleOutputPath = args.Span[++i];
            continue;
        }

        // Skip --staging, --in-toto
        if (a.StartsWith("--", StringComparison.Ordinal))
        {
            continue;
        }

        if (artifactPath is null)
        {
            artifactPath = a;
        }
    }

    if (identityToken is null || bundleOutputPath is null || artifactPath is null)
    {
        await Console.Error.WriteLineAsync("sign-bundle requires --identity-token, --bundle, and FILE").ConfigureAwait(false);
        return 2;
    }

    byte[] artifact = await File.ReadAllBytesAsync(artifactPath).ConfigureAwait(false);

    using HttpClient http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    TufClient tufClient = new TufClient(http, NullLogger<TufClient>.Instance);
    TrustedRoot trustedRoot = await tufClient.FetchPublicGoodTrustedRootAsync(CancellationToken.None).ConfigureAwait(false);

    SigningPipeline pipeline = new SigningPipeline(
        new StaticTokenProvider(identityToken),
        new FulcioClient(http, new Uri("https://fulcio.sigstore.dev/")),
        new RekorClient(http, new Uri("https://rekor.sigstore.dev/")),
        new CertificateVerifier(),
        NullLogger<SigningPipeline>.Instance);

    try
    {
        SigningResult result = await pipeline.RunAsync(
            artifact, payloadType: null, "sigstore", trustedRoot, CancellationToken.None).ConfigureAwait(false);
        await File.WriteAllTextAsync(bundleOutputPath, result.BundleJson).ConfigureAwait(false);
        return 0;
    }
    catch (Exception ex)
    {
        await Console.Error.WriteLineAsync(ex.Message).ConfigureAwait(false);
        return 1;
    }
}
```

Add using directives at the top of the file:
```csharp
using Sigstore.Signing;
using Sigstore.Oidc;
```

- [ ] **Step 2: Build and verify compilation**

Run: `dotnet build src/Sigstore.Conformance/Sigstore.Conformance.csproj --framework net9.0`
Expected: Build succeeded.

- [ ] **Step 3: Commit**

```bash
git add src/Sigstore.Conformance/ConformanceRunner.cs
git commit -m "feat: implement sign-bundle in conformance runner"
```

### Task A2: Remove `skip-signing` from conformance workflow

**Files:**
- Modify: `.github/workflows/conformance.yml`

- [ ] **Step 1: Remove `skip-signing: true`**

Delete the line `skip-signing: true` from the conformance workflow. The conformance suite's signing tests require `id-token: write` permission (already present).

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/conformance.yml
git commit -m "ci: enable signing conformance tests"
```

---

## Workstream B: Negative Validation Gaps

### Task B1: canonicalizedBody cross-check (wrong-hashedrekord)

**Files:**
- Modify: `src/Sigstore/Verification/VerificationPipeline.cs`

**xfails removed:** `test_verify*wrong-hashedrekord*_fail]` (6 tests: PATH and DIGEST × artifact/cert-and-sig/entry)

The `canonicalizedBody` field in a tlog entry is a base64-encoded JSON object. For `hashedrekord` entries, it contains the artifact hash, signature, and public key. The verification pipeline should decode this and cross-check against the bundle's actual content.

- [ ] **Step 1: Add `VerifyCanonicalizedBody` method**

After `ExtractTransparencyLogEntry`, add a call and implementation that:
1. Base64-decodes `entry.CanonicalizedBody`
2. Parses the JSON to extract `spec.signature.content` and `spec.data.hash.value`
3. Compares the hash against the bundle's `messageSignature.messageDigest.digest`
4. If they don't match, throws `TransparencyLogException`

```csharp
private static void VerifyCanonicalizedBody(TransparencyLogEntry entry, BundleProto model)
{
    if (entry.CanonicalizedBody.Length == 0)
    {
        return;
    }

    try
    {
        byte[] bodyBytes = entry.CanonicalizedBody.ToByteArray();
        // canonicalizedBody is base64-encoded in some bundle formats
        string bodyJson;
        try
        {
            bodyJson = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(
                System.Text.Encoding.UTF8.GetString(bodyBytes)));
        }
        catch (FormatException)
        {
            bodyJson = System.Text.Encoding.UTF8.GetString(bodyBytes);
        }

        using JsonDocument doc = JsonDocument.Parse(bodyJson);
        JsonElement root = doc.RootElement;

        if (!root.TryGetProperty("spec", out JsonElement spec))
        {
            return;
        }

        // Cross-check artifact hash
        if (model.ContentCase == BundleProto.ContentOneofCase.MessageSignature &&
            model.MessageSignature.MessageDigest is not null)
        {
            if (spec.TryGetProperty("data", out JsonElement data) &&
                data.TryGetProperty("hash", out JsonElement hash) &&
                hash.TryGetProperty("value", out JsonElement hashValue))
            {
                string? entryHash = hashValue.GetString();
                string bundleHash = Convert.ToHexString(
                    model.MessageSignature.MessageDigest.Digest.Span).ToLowerInvariant();
                if (entryHash is not null &&
                    !string.Equals(entryHash, bundleHash, StringComparison.OrdinalIgnoreCase))
                {
                    throw new TransparencyLogException(
                        "Step 6 (transparency log): canonicalized body hash does not match bundle message digest.");
                }
            }
        }

        // Cross-check signature
        if (spec.TryGetProperty("signature", out JsonElement sigEl) &&
            sigEl.TryGetProperty("content", out JsonElement sigContent))
        {
            string? entrySig = sigContent.GetString();
            byte[]? bundleSig = null;
            if (model.ContentCase == BundleProto.ContentOneofCase.MessageSignature)
            {
                bundleSig = model.MessageSignature.Signature.ToByteArray();
            }
            else if (model.ContentCase == BundleProto.ContentOneofCase.DsseEnvelope &&
                     model.DsseEnvelope.Signatures.Count > 0)
            {
                bundleSig = model.DsseEnvelope.Signatures[0].Sig.ToByteArray();
            }

            if (entrySig is not null && bundleSig is not null)
            {
                string bundleSigB64 = Convert.ToBase64String(bundleSig);
                if (!string.Equals(entrySig, bundleSigB64, StringComparison.Ordinal))
                {
                    throw new TransparencyLogException(
                        "Step 6 (transparency log): canonicalized body signature does not match bundle signature.");
                }
            }
        }
    }
    catch (TransparencyLogException)
    {
        throw;
    }
    catch (Exception)
    {
        // If we can't parse the body, skip the cross-check
    }
}
```

- [ ] **Step 2: Wire into RunAsync after ExtractTransparencyLogEntry**

Add `VerifyCanonicalizedBody(tlogEntry, model);` after `ExtractTransparencyLogEntry` in `RunAsync`.

- [ ] **Step 3: Build and test**

Run: `dotnet test tests/Sigstore.Tests/Sigstore.Tests.csproj --framework net9.0`
Expected: All pass.

- [ ] **Step 4: Remove wrong-hashedrekord from xfail list**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat: canonicalizedBody cross-check for hashedrekord entries"
```

### Task B2: DSSE envelope mismatch detection

**xfails removed:** `test_verify*PATH-dsse-mismatch*_fail]` `test_verify*PATH-rekor2-dsse-mismatch*_fail]` (4 tests)

The canonicalizedBody cross-check from B1 should also cover DSSE mismatches since the tlog body for DSSE entries contains the envelope. If B1 doesn't cover them, add DSSE-specific content matching in `VerifyCanonicalizedBody`.

- [ ] **Step 1: Test locally with a dsse-mismatch bundle to verify B1 covers it**
- [ ] **Step 2: If not covered, add DSSE envelope content comparison**
- [ ] **Step 3: Remove dsse-mismatch from xfail**
- [ ] **Step 4: Commit**

### Task B3: Remaining negative validations (batch)

**xfails removed:** All remaining `_fail` patterns.

These are tests where our verifier accepts bundles it should reject. For each category, add the appropriate guard check:

| Pattern | Fix |
|---------|-----|
| `checkpoint-bad-keyhint_fail` | Strict key hint validation in `SignedNoteVerifier.ValidateKeyHint` |
| `integrated-time-in-future_fail` | Already implemented in v0.3 — verify DIGEST mode handles it |
| `invalid-ct-key_fail` | Check SCT signer key exists in `trustedRoot.Ctlogs` |
| `intoto-log-entry-mismatch_fail` | Covered by canonicalizedBody cross-check (B1) |
| `intoto-missing-inclusion-proof_fail` | Require inclusion proof for in-toto bundles |
| `intoto-tsa-timestamp-outside-cert-validity_fail` | TSA timestamp must be within cert validity |
| `rekor2-timestamp-outside-trust-root_fail` | TSA cert must be within trusted root TSA validity window |
| `rekor2-timestamp-payload-mismatch_fail` | RFC 3161 timestamp hash must match the artifact |
| `rekor2-timestamp-untrusted_fail` | TSA certificate chain must be in trusted root |
| `DIGEST-signature-mismatch_fail` | For digest mode, verify signature if possible |
| `DIGEST-managed-key-wrong-key_fail` | Managed-key signature must verify against provided key |

- [ ] **Step 1: Implement each validation**
- [ ] **Step 2: Remove corresponding xfail patterns**
- [ ] **Step 3: Build and test**
- [ ] **Step 4: Commit**

### Task B4: Positive DIGEST-mode and checkpoint multi-sig tests

**xfails removed:** `test_verify*DIGEST-rekor2-dsse-happy-path]` `test_verify*DIGEST-happy-path-intoto-in-dsse*]` `test_verify*DIGEST-intoto-with-custom*]` `test_verify*rekor2-checkpoint-origin-not-first]`

- [ ] **Step 1: Investigate DIGEST-mode DSSE/intoto failures** — check if these need in-toto subject digest matching for pre-computed digests
- [ ] **Step 2: Investigate checkpoint origin-not-first** — parse checkpoints with multiple signature lines where the origin key is not the first signer
- [ ] **Step 3: Implement fixes**
- [ ] **Step 4: Remove from xfail**
- [ ] **Step 5: Commit**

---

## Final Tasks

### Task F1: Remove `skip-cpython-release-tests`

- [ ] **Step 1: Remove `skip-cpython-release-tests: true` from conformance.yml**
- [ ] **Step 2: Commit**

### Task F2: Empty the xfail list

- [ ] **Step 1: Remove the entire `xfail:` line from conformance.yml**
- [ ] **Step 2: Commit and push**

### Task F3: Run conformance and CI

- [ ] **Step 1: Trigger conformance and CI**
- [ ] **Step 2: Iterate on any remaining failures**
- [ ] **Step 3: All 3 conformance jobs green, all 9 CI jobs green**

### Task F4: CHANGELOG and release

- [ ] **Step 1: Add v0.4.0 CHANGELOG entry**
- [ ] **Step 2: Commit, push, merge PR**
- [ ] **Step 3: Create GitHub release v0.4.0**
- [ ] **Step 4: Verify NuGet publish succeeds**
