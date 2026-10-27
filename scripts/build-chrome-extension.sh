#!/usr/bin/env bash
# Build the load-unpacked Chrome extension zip (no signing, no Web Store).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
src="$root/extension/chrome"
version="$(node -p "require('$src/manifest.json').version")"
out="$root/dist-extension"
name="securevault-chrome-extension-$version"
rm -rf "$out/$name" "$out/$name.zip"
mkdir -p "$out/$name"
(cd "$src" && cp -R manifest.json background.js popup.html popup.js popup.css lib icons "$out/$name/")
# Guard: never ship a private key.
if grep -rIl "PRIVATE KEY" "$out/$name" >/dev/null; then
  echo "private key material found; refusing to package" >&2
  exit 1
fi
(cd "$out" && zip -qrX "$name.zip" "$name")
echo "$out/$name.zip"
