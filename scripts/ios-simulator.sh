#!/bin/sh
# Unsigned iOS simulator build, boot, and screenshots.
# Runs on the macOS GitHub runner. Linux can syntax-check this file with `sh -n`.
set -eu

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
UDID=$(PREFS="$PREFS" xcrun simctl list devices available -j | python3 "$PICK")
echo "Booting $UDID"
xcrun simctl boot "$UDID" || true
xcrun simctl bootstatus "$UDID" -b

xcrun simctl install "$UDID" "$APP"
xcrun simctl launch "$UDID" "$BUNDLE" || true
sleep 15
xcrun simctl io "$UDID" screenshot "$SCREEN_DIR/01-launch.png"
xcrun simctl terminate "$UDID" "$BUNDLE" || true

# Dummy vault only. The app reads SECUREVAULT_DEMO (simctl strips SIMCTL_CHILD_).
SIMCTL_CHILD_SECUREVAULT_DEMO=1 xcrun simctl launch "$UDID" "$BUNDLE" || true
sleep 35
xcrun simctl io "$UDID" screenshot "$SCREEN_DIR/02-demo-entries.png"
sleep 10
xcrun simctl io "$UDID" screenshot "$SCREEN_DIR/03-demo-entries-later.png" || true

if [ ! -s "$SCREEN_DIR/01-launch.png" ] || [ ! -s "$SCREEN_DIR/02-demo-entries.png" ]; then
  echo "Screenshots are missing." >&2
  exit 1
fi

ditto -c -k --keepParent "$APP" "$OUT/SecureVault-simulator-app.zip"
echo "Wrote $OUT/SecureVault-simulator-app.zip"
echo "Screenshots in $SCREEN_DIR"
