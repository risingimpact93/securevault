#!/usr/bin/env bash
# Build "SecureVault Safari.app" (containing app + Safari web extension), ad-hoc
# signed, and zip it. macOS only; needs Xcode and xcodegen. No notarization.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
chrome="$root/extension/chrome"
safari="$root/extension/safari"
res="$safari/Extension/Resources"
version="$(node -p "require('$chrome/manifest.json').version")"
out="$root/dist-extension"

# 1. Shared web extension files (same JS as Chrome) + derived manifest.
rm -rf "$res" && mkdir -p "$res"
(cd "$chrome" && cp -R background.js popup.html popup.js popup.css lib "$res/")
node "$root/scripts/safari-manifest.mjs" "$chrome/manifest.json" "$res/manifest.json"
if grep -rIl "PRIVATE KEY" "$res" >/dev/null; then echo "private key material found" >&2; exit 1; fi

[ "$(uname)" = "Darwin" ] || { echo "resources staged in $res (xcodebuild needs macOS)"; exit 0; }

# 2. Xcode project + build.
(cd "$safari" && xcodegen generate --quiet)
build="$root/target/safari-build"
rm -rf "$build"
xcodebuild -project "$safari/SecureVaultSafari.xcodeproj" -scheme SecureVaultSafari \
  -configuration Release -derivedDataPath "$build" \
  CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=YES DEVELOPMENT_TEAM= build | tail -n 20
app="$build/Build/Products/Release/SecureVault Safari.app"
codesign --verify --deep --strict "$app"
codesign -d --entitlements - "$app/Contents/PlugIns/SecureVaultSafariExtension.appex" >/dev/null

# 3. Zip.
mkdir -p "$out"
zip="$out/securevault-safari-extension-$version.zip"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
echo "$zip"
