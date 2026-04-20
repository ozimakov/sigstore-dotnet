# Contributing to sigstore-dotnet

Thank you for your interest in contributing. All forms of contribution are welcome — bug reports, feature requests, documentation improvements, and pull requests.

## Code of conduct

Please be respectful and constructive in all interactions. This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Reporting bugs and requesting features

Open an issue using the appropriate template. For bugs, include a minimal reproduction, the package version, target framework, and operating system. For feature requests, describe the motivation and sketch the desired API.

To report a **security vulnerability**, use [GitHub's private advisory system](https://github.com/ozimakov/sigstore-dotnet/security/advisories/new). Do not open a public issue. See [SECURITY.md](SECURITY.md) for the full policy.

## Development setup

**Prerequisites:** .NET SDK 8, 9, and 10 (all three required for multi-TFM builds).

```bash
git clone https://github.com/ozimakov/sigstore-dotnet.git
cd sigstore-dotnet
dotnet restore sigstore-dotnet.sln
dotnet build sigstore-dotnet.sln -c Release
```

## Running tests

### Unit tests (all three TFMs)

```bash
bash scripts/test-all-frameworks.sh
```

This builds the solution once in Release mode and then runs the test suite against net8.0, net9.0, and net10.0 in sequence. It exits with a non-zero status if any framework fails.

### Single framework

```bash
dotnet test sigstore-dotnet.sln -c Release --framework net10.0 --nologo
```

### Integration tests

The `Sigstore.Integration.Tests` project contains tests against the live Sigstore Public Good Instance. They are skipped by default because they require network access and are non-deterministic. To run them, remove the `Skip` attribute from the test and run:

```bash
dotnet test tests/Sigstore.Integration.Tests --framework net10.0 --nologo
```

### Conformance tests

The [sigstore-conformance](https://github.com/sigstore/sigstore-conformance) suite tests interoperability against other Sigstore clients. Conformance tests run automatically on the weekly schedule defined in `.github/workflows/conformance.yml`. To run them locally:

```bash
# Build and publish the conformance CLI
dotnet publish src/Sigstore.Conformance -c Release -o ./sigstore-tool

# Run the conformance suite (requires Python and sigstore-conformance installed)
# See https://github.com/sigstore/sigstore-conformance for setup instructions
```

## Code style

All formatting rules are defined in `.editorconfig` at the repository root. The project enforces `TreatWarningsAsErrors=true` — all compiler warnings are errors. Run `dotnet build` before opening a PR to confirm there are no warnings.

Key conventions:
- C# 12 language version (`LangVersion=12.0`)
- Nullable reference types enabled everywhere
- Implicit usings enabled
- No native cryptographic dependencies — stay within `System.Security.Cryptography`

## Pull requests

1. Fork the repository and create a branch from `main`
2. Make your changes with tests
3. Run `scripts/test-all-frameworks.sh` to verify all three TFMs pass
4. Update `CHANGELOG.md` under the `[Unreleased]` section
5. Update `docs/` if your change affects the public API or verification behaviour
6. Open a pull request — the PR template will guide you through the checklist

**Cryptographic and protocol changes** must reference the relevant specification (RFC, Sigstore client spec, protobuf definitions, or Rekor API documentation) in code comments where the rationale is not obvious.

## Commit messages

Use the imperative mood and keep the subject line under 72 characters. Reference related issues where applicable:

```
fix: wrap InvalidJsonException in BundleParseException (#42)
feat: add ForOciArtifact verification policy
docs: document RFC 3161 timestamp validation in architecture.md
```

## Release process (maintainers)

1. Update `CHANGELOG.md` — move items from `[Unreleased]` to a new `[X.Y.Z]` section with today's date
2. Update the `[Unreleased]` and `[X.Y.Z]` diff links at the bottom of `CHANGELOG.md`
3. Merge to `main`
4. Create a GitHub Release with tag `vX.Y.Z` and title `vX.Y.Z` — the release workflow publishes both NuGet packages automatically
