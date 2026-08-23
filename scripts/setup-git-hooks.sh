#!/usr/bin/env bash
# Install repository git hooks (author guard + no Cursor co-author trailers).
set -euo pipefail

root=$(git rev-parse --show-toplevel 2>/dev/null || true)
if [ -z "$root" ]; then
  echo "error: run from inside the Bucket Scanner git repository" >&2
  exit 1
fi

cd "$root"
chmod +x .githooks/pre-commit .githooks/commit-msg
git config core.hooksPath .githooks

echo "Installed git hooks from .githooks/"
echo "  - pre-commit: require FounderB author"
echo "  - commit-msg: block Co-authored-by: Cursor"
