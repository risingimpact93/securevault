#!/bin/sh
# Prepare src-tauri/gen/apple after `tauri ios init` (gen/apple is git-ignored).
# Idempotent; runs from `tauri ios build` (beforeBuildCommand in
# src-tauri/tauri.ios.conf.json) and from scripts/ios-simulator.sh.
#  1. Copy the committed AppIcon set into Assets.xcassets (init writes the
#     default Tauri icon set, which showed up as a blank home-screen icon).
#  2. Repair the Rust build phase if `tauri ios init` ran with FORCE_COLOR=0,
#     which inserts "0" before ${ARCHS:?} -> "Arch specified by Xcode was invalid. 0".
#  3. Make sure the app target sets ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon.
#     Some `tauri ios init` templates leave it out; then Xcode compiles no
#     Assets.car / CFBundleIcons and the home-screen icon is blank.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
APPLE="$ROOT/src-tauri/gen/apple"
ICONS="$ROOT/src-tauri/icons/ios/AppIcon.appiconset"

if [ ! -d "$APPLE" ]; then
  echo "ios-prepare: $APPLE is missing; run 'npx tauri ios init' first (with FORCE_COLOR unset)." >&2
  exit 0
fi

DEST="$APPLE/Assets.xcassets/AppIcon.appiconset"
mkdir -p "$DEST"
rm -f "$DEST"/*.png "$DEST"/Contents.json
cp "$ICONS"/*.png "$ICONS"/Contents.json "$DEST"/
echo "ios-prepare: AppIcon set copied ($(ls "$DEST" | wc -l | tr -d ' ') files)."

for f in "$APPLE/project.yml" $(find "$APPLE" -name project.pbxproj 2>/dev/null); do
  [ -f "$f" ] || continue
  if grep -Eq '(^|[^0-9A-Za-z_])0 *\$\{ARCHS' "$f"; then
    sed -E 's/(^|[^0-9A-Za-z_])0 *(\$\{ARCHS)/\1\2/g' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    echo "ios-prepare: removed stray '0' before \${ARCHS} in $f (FORCE_COLOR=0 during init)."
  fi
done

# 3. App icon name, in project.yml (survives xcodegen) and project.pbxproj (used by xcodebuild).
YML="$APPLE/project.yml"
if [ -f "$YML" ] && ! grep -q 'ASSETCATALOG_COMPILER_APPICON_NAME' "$YML"; then
  awk '
    { print }
    /^targets:/ { in_targets = 1 }
    in_targets && /^      base: *$/ && !done { print "        ASSETCATALOG_COMPILER_APPICON_NAME: AppIcon"; done = 1 }
  ' "$YML" > "$YML.tmp" && mv "$YML.tmp" "$YML"
  if grep -q 'ASSETCATALOG_COMPILER_APPICON_NAME' "$YML"; then
    echo "ios-prepare: added ASSETCATALOG_COMPILER_APPICON_NAME to project.yml."
  fi
fi
for f in $(find "$APPLE" -name project.pbxproj 2>/dev/null); do
  # Drop any existing value, then set AppIcon in every config that has a bundle id (the app target).
  awk '
    /ASSETCATALOG_COMPILER_APPICON_NAME = / { next }
    { print }
    /PRODUCT_BUNDLE_IDENTIFIER = / {
      match($0, /^[ \t]*/)
      print substr($0, 1, RLENGTH) "ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;"
    }
  ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  echo "ios-prepare: ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon set in $(grep -c 'ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;' "$f") build configuration(s) of $f."
done

# 4. NSFaceIDUsageDescription must survive `tauri ios init` regeneration.
#    tauri.ios.conf.json already points at Info.ios.plist; this copies the
#    string into generated Info.plist files if init dropped it.
FACEID_KEY="NSFaceIDUsageDescription"
FACEID_MSG="SecureVault 금고를 Face ID로 잠금 해제합니다."
for f in $(find "$APPLE" -name 'Info.plist' 2>/dev/null); do
  [ -f "$f" ] || continue
  if grep -q "$FACEID_KEY" "$f"; then
    continue
  fi
  python3 - "$f" "$FACEID_KEY" "$FACEID_MSG" <<'PY'
import sys
path, key, msg = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
needle = "</dict>"
insert = f"  <key>{key}</key>\n  <string>{msg}</string>\n"
idx = text.rfind(needle)
if idx < 0:
    raise SystemExit(0)
open(path, "w", encoding="utf-8").write(text[:idx] + insert + text[idx:])
print(f"ios-prepare: added {key} to {path}")
PY
done
