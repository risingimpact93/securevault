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
(cd "$chrome" && cp -R background.js popup.html popup.js popup.css lib icons "$res/")
node "$root/scripts/safari-manifest.mjs" "$chrome/manifest.json" "$res/manifest.json"
if grep -rIl "PRIVATE KEY" "$res" >/dev/null; then echo "private key material found" >&2; exit 1; fi

if [ "$(uname)" != "Darwin" ] || [ -n "${SV_STAGE_ONLY:-}" ]; then echo "resources staged in $res"; exit 0; fi

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
res="$app/Contents/PlugIns/SecureVaultSafariExtension.appex/Contents/Resources"
for f in manifest.json background.js popup.html lib/logic.js lib/fields.js icons/icon-128.png icons/icon-512.png; do
  [ -f "$res/$f" ] || { echo "missing $f at appex Resources root" >&2; exit 1; }
done

# 3. Zip.
mkdir -p "$out"
zip="$out/securevault-safari-extension-$version.zip"
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
echo "$zip"
