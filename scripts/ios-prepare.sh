#!/bin/sh
# Prepare src-tauri/gen/apple after `tauri ios init` (gen/apple is git-ignored).
# Idempotent; runs from `tauri ios build` (beforeBuildCommand in
# src-tauri/tauri.ios.conf.json) and from scripts/ios-simulator.sh.
#  1. Copy the committed AppIcon set into Assets.xcassets (init writes the
#     default Tauri icon set, which showed up as a blank home-screen icon).
#  2. Repair the Rust build phase if `tauri ios init` ran with FORCE_COLOR=0,
#     which inserts "0" before ${ARCHS:?} -> "Arch specified by Xcode was invalid. 0".
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
