#!/bin/bash
# build_only.sh — Mac cross-build of MacWSWindowing.dylib (auth-bind arm64e)
# Runs the exact build+verify steps from misc/deploy_macwswindowing.sh, minus device scp.
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/MacWSWindowing"
BUILT="$BUILD_DIR/.theos/obj/MacWSWindowing.dylib"
OUT="$SCRIPT_DIR/build-out"
mkdir -p "$OUT"

FIXUPS="$OUT/fixups.txt"
LOADCMDS="$OUT/otool-L.txt"
SOURCE_SNAPSHOT="$OUT/source-snapshot.json"
BUILD_MANIFEST="$OUT/build-manifest.json"

echo "==> [1/6] source snapshot"
python3 "$SCRIPT_DIR/macws_artifact_contract.py" snapshot \
    --root "$PROJECT_DIR" --manifest "$SOURCE_SNAPSHOT" || true

echo "==> [2/6] theos build (FINALPACKAGE=1 rootless)"
gmake -C "$BUILD_DIR" clean all \
    FINALPACKAGE=1 STRIP=0 OPTFLAG=-O2 \
    THEOS_PACKAGE_SCHEME=rootless GO_EASY_ON_ME=1

[ -s "$BUILT" ] || { echo "ERROR: build product missing: $BUILT"; exit 1; }

echo "==> [3/6] dyld_info fixups"
dyld_info -arch arm64e -fixups "$BUILT" > "$FIXUPS" || true
cf_count=$(awk '$2 == "__cfstring" && $4 == "auth-bind" && /key=DA/ { count++ } END { print count+0 }' "$FIXUPS")
plain_cf_count=$(awk '$2 == "__cfstring" && $4 == "bind" { count++ } END { print count+0 }' "$FIXUPS")
echo "auth-bind key=DA __cfstring count=$cf_count ; plain-bind count=$plain_cf_count"
if [ "$cf_count" -lt 1 ] || [ "$plain_cf_count" -ne 0 ]; then
    echo "ERROR: arm64e __cfstring fixup invariant FAILED (auth=$cf_count plain=$plain_cf_count)"
    exit 1
fi
echo "==> VERIFIED arm64e __cfstring fixups: auth-bind/key=DA"

echo "==> [4/6] otool load commands"
otool -L "$BUILT" > "$LOADCMDS"
if grep -q $'\t/Library/' "$LOADCMDS"; then
    echo "ERROR: rootful /Library load commands present"
    exit 1
fi
if ! grep -q $'\t@rpath/CydiaSubstrate.framework/CydiaSubstrate ' "$LOADCMDS"; then
    echo "ERROR: missing rootless @rpath Substrate dependency"
    exit 1
fi
echo "==> VERIFIED rootless load commands"

echo "==> [5/6] artifact manifest"
python3 "$SCRIPT_DIR/macws_artifact_contract.py" create \
    --root "$PROJECT_DIR" --binary "$BUILT" --manifest "$BUILD_MANIFEST" \
    --source-snapshot "$SOURCE_SNAPSHOT" || true

echo "==> [6/6] output"
cp -p "$BUILT" "$OUT/MacWSWindowing.dylib"
shasum -a 256 "$OUT/MacWSWindowing.dylib" | awk '{print $1}' > "$OUT/MacWSWindowing.sha256"
ls -l "$OUT/"
echo "BUILD_OK sha256=$(cat "$OUT/MacWSWindowing.sha256")"
