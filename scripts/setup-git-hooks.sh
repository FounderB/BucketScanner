#!/bin/sh
# Install repository git hooks (FounderB author guard).

set -euo pipefail

root=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$root" ]; then
  echo "error: run from inside the Bucket Scanner git repository" >&2
  exit 1
fi

cd "$root"
chmod +x .githooks/pre-commit .githooks/prepare-commit-msg .githooks/commit-msg scripts/setup-git-hooks.sh
git config core.hooksPath .githooks

echo "Installed git hooks from .githooks/"
echo "  - pre-commit: require FounderB author"
echo "  - prepare-commit-msg / commit-msg: drop injected Co-authored-by trailers"
