#!/data/data/com.termux/files/usr/bin/sh
# node-tester — Termux setup (Android, arm64)
# Run once:  sh termux-setup.sh
# Re-running is safe: existing binaries are kept, missing ones are retried.
set -e
cd "$(dirname "$0")"

echo "==> Installing Node.js and tools…"
pkg update -y || true
pkg install -y nodejs curl unzip tar

echo "==> Installing npm dependencies…"
npm install

mkdir -p bin
FAILED=0

# --- sing-box (primary engine, supports ALL protocols incl. hysteria2/tuic) ---
# Official releases: https://github.com/SagerNet/sing-box/releases
# NOTE: sing-box is GPL-3.0. It is downloaded here as a separate standalone
# binary; node-tester does not link or bundle its code.
SINGBOX_VER="1.14.4"
if [ ! -x bin/sing-box ]; then
  echo "==> Downloading sing-box v${SINGBOX_VER} (android-arm64)…"
  rm -f /tmp/sing-box.tar.gz
  if curl -fL -o /tmp/sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/sing-box-${SINGBOX_VER}-android-arm64.tar.gz"; then
    rm -rf /tmp/sing-box-extract && mkdir -p /tmp/sing-box-extract
    tar -xzf /tmp/sing-box.tar.gz -C /tmp/sing-box-extract
    FOUND=$(find /tmp/sing-box-extract -name 'sing-box' -type f | head -n 1)
    if [ -n "$FOUND" ]; then cp "$FOUND" bin/sing-box; fi
  else
    echo "WARN: sing-box download failed (network or release moved)."
  fi
fi

# --- Xray (fallback engine for xray-compatible protocols) ---
# Official releases: https://github.com/XTLS/Xray-core/releases
# Uses the version-independent "latest" URL so it cannot rot when Xray
# publishes a new version.
if [ ! -x bin/xray ]; then
  echo "==> Downloading Xray (android-arm64, latest)…"
  rm -f /tmp/xray.zip
  if curl -fL -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-android-arm64-v8a.zip"; then
    rm -rf /tmp/xray-bin && mkdir -p /tmp/xray-bin
    unzip -o /tmp/xray.zip -d /tmp/xray-bin >/dev/null
    if [ -f /tmp/xray-bin/xray ]; then cp /tmp/xray-bin/xray bin/xray; fi
  else
    echo "WARN: Xray download failed (network or release moved)."
  fi
fi

chmod +x bin/sing-box bin/xray 2>/dev/null || true

echo ""
echo "==> Verifying core binaries…"
if [ -x bin/sing-box ]; then
  echo "    sing-box: OK — $(./bin/sing-box version | head -n 1)"
else
  echo "    sing-box: MISSING — download it manually from https://github.com/SagerNet/sing-box/releases (android-arm64 .tar.gz), extract, and place the 'sing-box' file in bin/"
  FAILED=1
fi
if [ -x bin/xray ]; then
  echo "    xray:     OK — $(./bin/xray version | head -n 1)"
else
  echo "    xray:     MISSING — download Xray-android-arm64-v8a.zip from https://github.com/XTLS/Xray-core/releases, extract, and place the 'xray' file in bin/ (optional: only needed for XHTTP nodes when sing-box is present)"
fi

echo ""
if [ "$FAILED" = "1" ]; then
  echo "Setup finished WITH ERRORS: sing-box is required for testing. Fix the download above and re-run: sh termux-setup.sh"
  exit 1
fi
echo "Done. Optional, to get ready-output files copied into Downloads:"
echo "    termux-setup-storage"
echo "Then start with:  sh start.sh   and open http://localhost:3000"
