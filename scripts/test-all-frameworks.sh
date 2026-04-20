#!/usr/bin/env bash
set -euo pipefail

DOTNET=${DOTNET_PATH:-/usr/local/share/dotnet/dotnet}
FRAMEWORKS=("net8.0" "net9.0" "net10.0")
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Using dotnet: $($DOTNET --version)"
echo "==> Repo root: $REPO_ROOT"
echo

echo "==> Building solution (all frameworks)..."
"$DOTNET" build "$REPO_ROOT/sigstore-dotnet.sln" -c Release --nologo
echo

FAILED=()

for tfm in "${FRAMEWORKS[@]}"; do
    echo "==> Testing $tfm..."
    if "$DOTNET" test "$REPO_ROOT/sigstore-dotnet.sln" \
        -c Release \
        --no-build \
        --framework "$tfm" \
        --nologo \
        --logger "console;verbosity=minimal"; then
        echo "    PASS: $tfm"
    else
        echo "    FAIL: $tfm"
        FAILED+=("$tfm")
    fi
    echo
done

if [ ${#FAILED[@]} -eq 0 ]; then
    echo "==> All frameworks passed."
else
    echo "==> FAILED frameworks: ${FAILED[*]}"
    exit 1
fi
