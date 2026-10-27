#!/usr/bin/env bash
# Build "SecureVault Safari.app" on your own Mac, signed with your free Apple
# "Personal Team" (Apple Development certificate), install it to /Applications
# and launch it once. Nothing is written to the repo except the git-ignored
# generated project and staged Resources; the team ID only lives in this shell.
#
#   SV_TEAM_ID=ABCDE12345 bash scripts/build-safari-local.sh
#
# Without SV_TEAM_ID the script reads the team (OU) from the first
# "Apple Development" certificate in your login keychain.
set -euo pipefail
[ "$(uname)" = "Darwin" ] || { echo "macOS only" >&2; exit 1; }
root="$(cd "$(dirname "$0")/.." && pwd)"
safari="$root/extension/safari"
command -v xcodegen >/dev/null || { echo "xcodegen missing: brew install xcodegen" >&2; exit 1; }

team="${SV_TEAM_ID:-}"
if [ -z "$team" ]; then
  team="$(security find-certificate -c "Apple Development" -p 2>/dev/null \
    | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*OU *= *\([A-Z0-9]\{10\}\).*/\1/p' | head -n1)"
fi
[ -n "$team" ] || { echo "No team. Xcode > Settings > Accounts: add your Apple ID (Personal Team), then rerun or set SV_TEAM_ID." >&2; exit 1; }
echo "Signing team: $team"

# 1. Stage shared JS + manifest (same as CI).
SV_STAGE_ONLY=1 bash "$root/scripts/build-safari-extension.sh" >/dev/null
(cd "$safari" && xcodegen generate --quiet)

# 2. Build with automatic signing (Xcode creates the dev profile if needed).
build="$root/target/safari-local"
rm -rf "$build"
xcodebuild -project "$safari/SecureVaultSafari.xcodeproj" -scheme SecureVaultSafari \
  -configuration Release -derivedDataPath "$build" -allowProvisioningUpdates \
  CODE_SIGN_STYLE=Automatic CODE_SIGN_IDENTITY="Apple Development" DEVELOPMENT_TEAM="$team" \
  build | tail -n 15
app="$build/Build/Products/Release/SecureVault Safari.app"
codesign --verify --deep --strict "$app"
codesign -dv "$app/Contents/PlugIns/SecureVaultSafariExtension.appex" 2>&1 | grep -E "Authority=Apple Development|TeamIdentifier" \
  || { echo "appex is not signed with an Apple Development identity" >&2; exit 1; }

# 3. Install and register.
osascript -e 'quit app "SecureVault Safari"' >/dev/null 2>&1 || true
rm -rf "/Applications/SecureVault Safari.app"
ditto "$app" "/Applications/SecureVault Safari.app"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "/Applications/SecureVault Safari.app"
open "/Applications/SecureVault Safari.app"
sleep 2
pluginkit -mAvvv -p com.apple.Safari.web-extension | grep -A3 com.securevault.safari.extension || true

cat <<'MSG'

Next steps:
  1. Quit Safari completely (Cmd+Q) and open it again.
  2. Safari > Settings > Extensions: tick "SecureVault". A Personal Team signed
     extension does not need "Allow unsigned extensions".
  3. If it still is not listed, run the diagnostics in docs/autofill-install.md.
  Note: if a free Personal Team signature or profile expires, rerun this script.
MSG
