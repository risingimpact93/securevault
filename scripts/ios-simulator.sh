#!/bin/sh
# Unsigned iOS simulator build, boot, and screenshots.
# Runs on the macOS GitHub runner. Linux can syntax-check this file with `sh -n`.
set -eu
# FORCE_COLOR=0 makes `tauri ios init` write "0 ${ARCHS:?}" into the Xcode build phase.
unset FORCE_COLOR NO_COLOR CLICOLOR_FORCE 2>/dev/null || true

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
OUT="$ROOT/src-tauri/gen/apple/ci-out"
mkdir -p "$OUT"
SCREEN_DIR="$OUT/screenshots"
mkdir -p "$SCREEN_DIR"

if ! command -v xcrun >/dev/null 2>&1; then
  echo "xcrun is missing. This script is for the macOS runner." >&2
  exit 1
fi

EXISTING=$(find src-tauri/gen/apple -name '*.xcodeproj' 2>/dev/null | head -n 1 || true)
if [ ! -d src-tauri/gen/apple ] || [ -z "$EXISTING" ]; then
  echo "Generating the Xcode project (src-tauri/gen/apple is not committed)."
  npx tauri ios init --ci --skip-targets-install
fi
PBX=$(find src-tauri/gen/apple -name project.pbxproj | head -n 1)
echo "After init, AppIcon name lines in pbxproj: $(grep -c 'ASSETCATALOG_COMPILER_APPICON_NAME' "$PBX" || true)"

sh scripts/ios-prepare.sh
if ! grep -q 'ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon;' "$PBX"; then
  echo "ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon is missing from $PBX after ios-prepare." >&2
  exit 1
fi
if grep -Eq '(^|[^0-9A-Za-z_])0 *\$\{ARCHS' src-tauri/gen/apple/project.yml 2>/dev/null; then
  echo "Stray 0 before ARCHS is still present." >&2
  exit 1
fi

PROJ=$(find src-tauri/gen/apple -name '*.xcodeproj' -print | head -n 1)
SCHEME_FILE=$(find src-tauri/gen/apple -name '*.xcscheme' -print | head -n 1)
SCHEME=$(basename "$SCHEME_FILE" .xcscheme)
echo "Xcode project: $PROJ"
echo "Scheme: $SCHEME"

echo "Trying tauri ios build (simulator, debug)."
set +e
npx tauri ios build --target aarch64-sim --debug --ci
TAURI_STATUS=$?
set -e
if [ "$TAURI_STATUS" -ne 0 ]; then
  echo "tauri ios build exited $TAURI_STATUS. Building unsigned with xcodebuild."
  xcodebuild \
    -project "$PROJ" \
    -scheme "$SCHEME" \
    -configuration Debug \
    -sdk iphonesimulator \
    -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$OUT/DerivedData" \
    CODE_SIGNING_ALLOWED=NO \
    CODE_SIGNING_REQUIRED=NO \
    CODE_SIGN_IDENTITY="" \
    build
fi

APP=$(find src-tauri/gen/apple "$OUT" "$ROOT/target" -name 'SecureVault.app' -type d 2>/dev/null | grep iphonesimulator | head -n 1 || true)
if [ -z "$APP" ]; then
  APP=$(find src-tauri/gen/apple "$OUT" "$ROOT/target" -name 'SecureVault.app' -type d 2>/dev/null | head -n 1 || true)
fi
if [ -z "$APP" ] || [ ! -d "$APP" ]; then
  echo "SecureVault.app was not produced." >&2
  exit 1
fi
echo "Simulator app: $APP"

# Icons must be compiled into the bundle (blank home-screen icon in 0.4.0).
if [ ! -s "$APP/Assets.car" ]; then
  echo "Assets.car is missing from $APP; the AppIcon set was not compiled." >&2
  exit 1
fi
if ! /usr/libexec/PlistBuddy -c "Print :CFBundleIcons:CFBundlePrimaryIcon" "$APP/Info.plist"; then
  echo "CFBundleIcons is missing from Info.plist." >&2
  exit 1
fi
ls -la "$APP/Assets.car" "$APP"/AppIcon*.png 2>/dev/null || true

BUNDLE=com.securevault.ios
if [ -f "$APP/Info.plist" ]; then
  FOUND=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP/Info.plist" 2>/dev/null || true)
  if [ -n "$FOUND" ]; then
    BUNDLE=$FOUND
  fi
fi
echo "Bundle id: $BUNDLE"

echo "Available simulators:"
xcrun simctl list devices available

PICK=$OUT/pick-device.py
cat > "$PICK" <<'PY'
import json, os, sys
prefs = [item for item in os.environ.get("PREFS", "").split("|") if item]
data = json.load(sys.stdin)
devices = []
for items in data.get("devices", {}).values():
    for device in items:
        if device.get("isAvailable", True):
            devices.append(device)
for pref in prefs:
    for device in devices:
        if device.get("name") == pref:
            sys.stderr.write("chosen: %s %s\n" % (device["name"], device["udid"]))
            print(device["udid"])
            raise SystemExit(0)
iphones = [device for device in devices if "iPhone" in device.get("name", "")]
iphones.sort(key=lambda device: device.get("name", ""), reverse=True)
if not iphones:
    sys.stderr.write("no iPhone simulator\n")
    raise SystemExit(1)
device = iphones[0]
sys.stderr.write("chosen fallback: %s %s\n" % (device["name"], device["udid"]))
print(device["udid"])
PY

PREFS="iPhone 14 Pro Max|iPhone 15 Pro Max|iPhone 16 Pro Max|iPhone 16 Plus|iPhone 16 Pro|iPhone 15 Pro|iPhone 15 Plus|iPhone 15|iPhone 17 Pro Max|iPhone 17 Pro|iPhone 17 Plus|iPhone 17|iPhone 16|iPhone SE (3rd generation)"
# Create an iPhone 14 Pro Max simulator (430x932 pt) on the newest iOS runtime if none exists.
if ! xcrun simctl list devices available | grep -q "iPhone 14 Pro Max ("; then
  RUNTIME=$(xcrun simctl list runtimes available -j | python3 -c 'import json,sys; r=[x for x in json.load(sys.stdin)["runtimes"] if x.get("platform")=="iOS" or "iOS" in x.get("name","")]; r.sort(key=lambda x: [int(p) for p in x["version"].split(".")]); print(r[-1]["identifier"] if r else "")')
  if [ -n "$RUNTIME" ]; then
    xcrun simctl create "iPhone 14 Pro Max" com.apple.CoreSimulator.SimDeviceType.iPhone-14-Pro-Max "$RUNTIME" || echo "could not create iPhone 14 Pro Max on $RUNTIME"
  fi
fi
UDID=$(xcrun simctl list devices available -j | PREFS="$PREFS" python3 "$PICK")
echo "Booting $UDID"
xcrun simctl boot "$UDID" || true
xcrun simctl bootstatus "$UDID" -b

xcrun simctl install "$UDID" "$APP"
xcrun simctl launch "$UDID" "$BUNDLE" || true
sleep 15
xcrun simctl io "$UDID" screenshot "$SCREEN_DIR/01-launch.png"

# The launch screen calls ios_plugin_status, which pings the Swift
# vault-access plugin and writes a marker into the app data directory.
DATA=$(xcrun simctl get_app_container "$UDID" "$BUNDLE" data)
MARKER=$(find "$DATA" -name plugin-status.txt 2>/dev/null | head -n 1 || true)
if [ -z "$MARKER" ]; then
  echo "plugin-status.txt was not written; ios_plugin_status did not run." >&2
  exit 1
fi
echo "vault-access plugin status: $(cat "$MARKER")"
cp "$MARKER" "$OUT/plugin-status.txt"
if ! grep -q '^ok vault-access io-roundtrip' "$MARKER"; then
  echo "The vault-access plugin is not registered or did not answer." >&2
  exit 1
fi
xcrun simctl terminate "$UDID" "$BUNDLE" || true
sleep 4
xcrun simctl io "$UDID" screenshot "$SCREEN_DIR/00-home-screen.png" || true

# Dummy vault only. The app reads SECUREVAULT_DEMO (simctl strips SIMCTL_CHILD_).
SIMCTL_CHILD_SECUREVAULT_DEMO=1 xcrun simctl launch "$UDID" "$BUNDLE" || true
sleep 35
xcrun simctl io "$UDID" screenshot "$SCREEN_DIR/02-demo-entries.png"
sleep 10
xcrun simctl io "$UDID" screenshot "$SCREEN_DIR/03-demo-entries-later.png" || true

# 0.5.0 iOS UI: one relaunch per view, dummy vault only.
xcrun simctl status_bar "$UDID" override --time 9:41 --batteryState charged --batteryLevel 100 || true
shoot_view() {
  name="$1"; view="$2"; theme="$3"; wait="${4:-14}"
  xcrun simctl terminate "$UDID" "$BUNDLE" || true
  sleep 2
  SIMCTL_CHILD_SECUREVAULT_DEMO=1 SIMCTL_CHILD_SECUREVAULT_DEMO_VIEW="$view" SIMCTL_CHILD_SECUREVAULT_DEMO_THEME="$theme" \
    xcrun simctl launch "$UDID" "$BUNDLE" || true
  sleep "$wait"
  xcrun simctl io "$UDID" screenshot "$SCREEN_DIR/$name.png" || echo "screenshot $name failed"
}
shoot_view 10-list-dark list dark 18
shoot_view 11-list-scrolled scrolled dark
shoot_view 12-detail-dark detail dark
shoot_view 13-edit-dark edit dark
shoot_view 14-settings-dark settings dark
shoot_view 15-generator-dark generator dark
shoot_view 16-swipe-dark swipe dark
shoot_view 17-new-item-dark new dark
shoot_view 18-replace-confirm-dark replace dark
shoot_view 24-replace-confirm-light replace light
shoot_view 20-list-light list light
shoot_view 21-detail-light detail light
shoot_view 22-settings-light settings light
shoot_view 23-edit-light edit light

if [ ! -s "$SCREEN_DIR/01-launch.png" ] || [ ! -s "$SCREEN_DIR/02-demo-entries.png" ]; then
  echo "Screenshots are missing." >&2
  exit 1
fi

ditto -c -k --keepParent "$APP" "$OUT/SecureVault-simulator-app.zip"
echo "Wrote $OUT/SecureVault-simulator-app.zip"
echo "Screenshots in $SCREEN_DIR"
