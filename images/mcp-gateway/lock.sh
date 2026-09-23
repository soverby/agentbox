#!/bin/sh
# Regenerate requirements.lock from requirements.in (hashes for every platform).
set -eu
cd "$(dirname "$0")"
uv pip compile --universal --python-version 3.13 --generate-hashes -q requirements.in -o requirements.lock
