# Getting Started

## Installation

```
dotnet add package Sigstore.Net
```

## Verification with dependency injection

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

## Signing with dependency injection

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
    }
}
```

## Managed-key verification

```csharp
string publicKeyPem = await File.ReadAllTextAsync("cosign.pub");

VerificationResult result = await verifier.VerifyWithKeyAsync(
    bundleJson, artifact, publicKeyPem,
    trustedRootJson: trustedRoot,
    CancellationToken.None);
```

## Batch signing

Sign multiple artifacts with a single OIDC token and certificate:

```csharp
byte[][] artifacts = { fileA, fileB, fileC };
IReadOnlyList<SigningResult> results = await signer.SignBatchAsync(
    artifacts, CancellationToken.None);
```

## Staging environment

For testing against non-production Sigstore infrastructure:

```csharp
builder.Services.AddSigstoreSigning(options =>
{
    var staging = SigstoreSigningOptions.Staging();
    options.FulcioUrl = staging.FulcioUrl;
    options.RekorUrl = staging.RekorUrl;
});
```
