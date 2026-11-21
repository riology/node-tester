#!/data/data/com.termux/files/usr/bin/sh
# node-tester — Termux setup (Android, arm64)
# Run once:  sh termux-setup.sh
set -e
echo "==> Installing Node.js…"
pkg update -y || true
pkg install -y nodejs curl unzip

echo "==> Installing npm dependencies…"
cd "$(dirname "$0")"
npm install

mkdir -p bin

# --- sing-box (primary engine, supports ALL protocols incl. hysteria2/tuic) ---
# Official releases: https://github.com/SagerNet/sing-box/releases
# NOTE: sing-box is GPL-3.0. It is downloaded here as a separate standalone
# binary; node-tester does not link or bundle its code.
SINGBOX_VER="1.11.15"
if [ ! -x bin/sing-box ]; then
  echo "==> Downloading sing-box v${SINGBOX_VER} (android-arm64)…"
  curl -L -o /tmp/sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/sing-box-${SINGBOX_VER}-android-arm64.tar.gz" || \
    echo "WARN: sing-box download failed — check the version/arch at https://github.com/SagerNet/sing-box/releases and place the binary at bin/sing-box manually."
  if [ -f /tmp/sing-box.tar.gz ]; then
    tar -xzf /tmp/sing-box.tar.gz -C /tmp || true
    find /tmp -name 'sing-box' -type f -path "*${SINGBOX_VER}*" -exec cp {} bin/sing-box \; || true
  fi
fi

# --- Xray (fallback engine for xray-compatible protocols) ---
# Official releases: https://github.com/XTLS/Xray-core/releases
XRAY_VER="v25.3.6"
if [ ! -x bin/xray ]; then
  echo "==> Downloading Xray ${XRAY_VER} (android-arm64)…"
  curl -L -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-android-arm64-v8a.zip" || \
    echo "WARN: Xray download failed — check https://github.com/XTLS/Xray-core/releases and place the binary at bin/xray manually."
  if [ -f /tmp/xray.zip ]; then
    unzip -o /tmp/xray.zip -d /tmp/xray-bin >/dev/null || true
    [ -f /tmp/xray-bin/xray ] && cp /tmp/xray-bin/xray bin/xray || true
  fi
fi

chmod +x bin/sing-box bin/xray 2>/dev/null || true
echo ""
echo "Done. Optional, to get ready-output files copied into Downloads:"
echo "    termux-setup-storage"
echo "Then start with:  sh start.sh   and open http://localhost:3000"
