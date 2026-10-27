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
  # First valid "Apple Development" identity; its certificate subject OU is the team ID.
  ident="$(security find-identity -v -p codesigning | awk '/"Apple Development:/{print $2; exit}')"
  if [ -n "$ident" ]; then
    team="$(security find-certificate -a -Z -p -c "Apple Development" 2>/dev/null \
      | awk -v h="$ident" '/^SHA-1 hash:/{keep=($3==h)} keep' \
      | openssl x509 -noout -subject 2>/dev/null | sed -n 's/.*OU *= *\([A-Z0-9]\{10\}\).*/\1/p' | head -n1)"
  fi
fi
if [ -z "$team" ]; then
  cat >&2 <<'HELP'
No Apple Development signing identity found.
  1. Open Xcode > Settings > Accounts, click +, add your Apple ID (a free "Personal Team" is created).
  2. Select the team > Manage Certificates > + > Apple Development.
  3. Rerun this script (or set SV_TEAM_ID=<10-char team ID shown in Accounts>).
HELP
  exit 1
fi
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
  ENABLE_HARDENED_RUNTIME=NO CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO \
  build | tail -n 15
app="$build/Build/Products/Release/SecureVault Safari.app"
codesign --verify --deep --strict "$app"
# Safari 26 treats ad-hoc as unsigned: both bundles must carry a real TeamIdentifier.
for b in "$app" "$app/Contents/PlugIns/SecureVaultSafariExtension.appex"; do
  info="$(codesign -dvvv "$b" 2>&1)"
  tid="$(printf '%s\n' "$info" | sed -n 's/^TeamIdentifier=//p')"
  if [ -z "$tid" ] || [ "$tid" = "not set" ] || printf '%s' "$info" | grep -q "Signature=adhoc"; then
    echo "not signed with a team: $b" >&2; exit 1
  fi
  echo "signed: $(basename "$b")  TeamIdentifier=$tid"
done

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
