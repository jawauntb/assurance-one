#!/usr/bin/env bash
# Fails if any file under tests/ changed since tests.lock was written.
set -euo pipefail
cd "$(dirname "$0")/.."
find tests -type f -not -path '*/__pycache__/*' | LC_ALL=C sort | xargs sha256sum | diff - tests.lock
echo "tests.lock OK"
