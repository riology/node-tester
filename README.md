# node-tester

**A local proxy node tester with ready-to-import output.**
Feed it raw nodes or subscription links, it *really connects* through each node on **your own network**, measures latency + speed, and hands you back clean, sorted, ready-to-use subscriptions — no copying or moving files around.

It merges two earlier projects:
- **tester.py** — the original Python/Xray bulk node tester (testing logic ported to Node here; its parser is *not* used)
- **URI-link-generator** — the parser/normaliser/output engine (`src/vpnCore.js`, MIT, see Credits)

```
 SOURCES                      PARSE                 TEST (your network)            READY OUTPUT
 ───────                      ─────                 ───────────────────            ────────────
 paste / file / clipboard ─┐
 subscription URLs ────────┼─► vpnCore          ─► Stage 1 latency (all, x10) ─►  live /sub/tested link + QR
 Clash YAML / sing-box     │   normalise, dedup     Stage 2 speed (top N, x3)     Copy Top 15 / Copy All
 JSON / Xray JSON ─────────┘   + Clash converter ─► sing-box (all protocols)     Downloads: base64 brackets,
                                                    Xray (fallback)              sing-box JSON, Clash YAML,
                                                                                 Xray JSON, raw URIs
```

## Why local?
A cloud tester measures the *cloud's* network. node-tester runs as a small server on your own device (`http://localhost:3000`), so fetching subscriptions and testing nodes use **your real connection** — the results are the speeds *you* will actually get. The web UI is just the control panel; all testing happens natively on the device running it.

## Protocols
VLESS (TLS / REALITY / WS / gRPC / XHTTP*), VMess, Shadowsocks (SIP002 + legacy), Trojan, Hysteria2 / Hy2, TUIC.
Testing is routed per node by core compatibility: **sing-box tests everything**; Xray is used as a fallback for Xray-compatible nodes when sing-box is missing. Unsupported Clash types (snell, ssr, …) are skipped with a recorded warning.
\* XHTTP nodes are Xray-only (vpnCore flags them sing-box-incompatible) and need the Xray binary.

## Accuracy: two-stage testing
tester.py ran 20 nodes × 5 MB at the same time — they all fought for the same bandwidth, so the numbers were only a rough ranking. node-tester fixes that:
1. **Stage 1 — latency** for *all* nodes (concurrency 10, Cloudflare `generate_204`, 6 s timeout).
2. **Stage 2 — speed** only for the **top 50 by latency** (configurable), at **concurrency 3**, 5 MB download from speed.cloudflare.com.
Dead nodes always come back with a reason (`timeout`, `tls`, `connect`, `core-exit`, `core binary not found`, …) — nothing fails silently.

---

# Guide — Windows

## What you need
- Windows 10/11 (64-bit)
- [Node.js](https://nodejs.org) **18 or newer** (LTS recommended)
- The two core binaries (step 3) — sing-box is the important one, it tests every protocol

## Step 1 — Install Node.js
Download the LTS installer from [nodejs.org](https://nodejs.org) and install it (default options are fine). Verify in a new PowerShell or Command Prompt window:
```bat
node --version
npm --version
```

## Step 2 — Get node-tester
Download the project ZIP from GitHub and extract it, or clone it:
```bat
git clone <repo-url> node-tester
cd node-tester
npm install
```

## Step 3 — Add the core binaries
Create a `bin` folder inside the project (next to `server.js`) and put the binaries in it with **exactly these names**:

| File | Download | Notes |
|---|---|---|
| `bin\sing-box.exe` | [SagerNet/sing-box releases](https://github.com/SagerNet/sing-box/releases) → `sing-box-<version>-windows-amd64.zip` | Extract, rename/move `sing-box.exe` into `bin\` |
| `bin\xray.exe` | [XTLS/Xray-core releases](https://github.com/XTLS/Xray-core/releases) → `Xray-windows-64.zip` | Extract, move `xray.exe` into `bin\`. Optional but recommended (needed for XHTTP nodes) |

Alternative: instead of `bin\`, point environment variables at the binaries wherever they are (PowerShell, per session):
```powershell
$env:SING_BOX_BIN = "C:\tools\sing-box.exe"
$env:XRAY_BIN = "C:\tools\xray.exe"
```
Binaries already on your `PATH` are also found automatically.

## Step 4 — Run it
Double-click **`start.bat`**, or from a terminal in the project folder:
```bat
npm start
```
You should see `node-tester running at http://localhost:3000`. **Keep that window open** while you use it — closing it (or pressing `Ctrl+C`) stops the server.

Open **http://localhost:3000** in your browser. Check the health panel / open `http://localhost:3000/api/health` — it should report the sing-box (and Xray) binaries as found. If Windows Firewall pops up asking about Node.js, allow it on Private networks so the local server and the core processes can work.

To use a different port: `set PORT=3001 && npm start` (Command Prompt) or `$env:PORT=3001; npm start` (PowerShell).

## Step 5 — Use it
See [How to use](#how-to-use-same-on-windows-and-android) below. On Windows your ready-output files land in the project's `outputs\` folder.

---

# Guide — Android (Termux)

There is no APK — node-tester runs inside **Termux** and you use it from your phone browser, but all testing runs natively on your phone, on your mobile/Wi-Fi network.

## What you need
- An Android phone (arm64 — virtually all modern phones)
- **Termux installed from [F-Droid](https://f-droid.org/packages/com.termux/) or [GitHub](https://github.com/termux/termux-app/releases)** — do *not* use the Play Store version, it's outdated and broken
- ~200 MB free space (Node.js + the two cores)

## Step 1 — First-time Termux setup
Open Termux and run:
```sh
pkg update -y
pkg install -y git nodejs
```

## Step 2 — Get node-tester
Clone it (recommended — easy to update later with `git pull`):
```sh
git clone <repo-url> node-tester
cd node-tester
```
Or, if you downloaded the ZIP on the phone instead: run `termux-setup-storage` once, copy the ZIP to your Downloads, then in Termux:
```sh
cd ~/storage/downloads
unzip node-tester.zip -d ~/node-tester
cd ~/node-tester
```

## Step 3 — Run the setup script (once)
```sh
sh termux-setup.sh
```
This installs the npm dependencies and downloads **sing-box** and **Xray** (android-arm64) into `bin/`. If a download warning appears (version rotated), download the current android-arm64 release manually from the link printed and place the binary at `bin/sing-box` / `bin/xray`.

Optional but recommended:
```sh
termux-setup-storage
```
This grants Termux access to shared storage, so after every test your ready-output files are **also copied to `Downloads/node-tester/`** — where your file manager and other apps can see them, no manual moving.

## Step 4 — Start it (every time you want to use it)
```sh
cd ~/node-tester
sh start.sh
```
Leave Termux running in the background, open your browser, and go to **http://localhost:3000**.

Two Android survival tips for long test runs:
- Run `termux-wake-lock` in Termux before a big test so Android doesn't freeze Termux when the screen turns off.
- In your phone's Settings → Apps → Termux → Battery, set battery usage to **Unrestricted** — aggressive battery savers (especially HyperOS/Xiaomi, Samsung, Oppo) otherwise kill Termux mid-test.

To stop the server: switch back to Termux and press `Ctrl+C` (Termux shows `CTRL` on the extra-keys row; tap `CTRL` then `c`).

## Step 5 — Use it
See [How to use](#how-to-use-same-on-windows-and-android) below. Tested results are in the UI immediately; files are in `~/node-tester/outputs/` and, with storage set up, in `Downloads/node-tester/`.

## Updating
```sh
cd ~/node-tester
git pull
npm install
```
(If you installed from ZIP, just extract the new ZIP over the old folder — your `data/` and `outputs/` are not part of the download.)

---

# How to use (same on Windows and Android)

1. **Add sources** — any mix of:
   - **Paste** raw links / a base64 subscription blob into the text box, or use the **Paste from clipboard** button.
   - **Load a file** (e.g. an old `nodes.txt`) with the file picker — no Termux path typing.
   - **Subscription URLs:** paste one or more subscription links, press **Fetch**. You'll see how many nodes each source gave and, when the provider sends it, your usage/expiry from the `subscription-userinfo` header. You can **save** sources so next time is one tap — they're stored only on your device (see Privacy).
2. **Settings** (defaults are sensible): how many of the fastest-latency nodes get a speed test (50), speed-test size (5 MB), target working count. Lower the stage-2 count on a slow/expensive mobile connection.
3. **Press Test nodes.** Watch live progress: stage 1 latency for everything, then stage 2 speed for the best ones. The results table fills in live — protocol, name, ping, Mbps — and every dead node shows *why* it died. Sort by Mbps or ping, filter by protocol or name.
4. **Take the ready output** — this is the point of the tool, no file surgery:
   - **Copy Top 15** / **Copy All Working** buttons (base64 subscription format — paste straight into any client).
   - **Download** buttons: base64 text, sing-box JSON, Clash YAML, Xray JSON, raw URI list.
   - **Live subscription link:** copy `http://localhost:3000/sub/tested` (or scan its QR) into AVX / Hiddify / v2rayNG as a subscription. While node-tester is running, that link always serves your *latest tested working set* — re-run a test and the client just updates. Formats: `?target=singbox` (default for sing-box clients), `?target=clash`, `?target=xray-json`, `?target=raw`.
   - The same outputs are written as files to `outputs/` (and to `Downloads/node-tester/` on Android with storage set up) — see the file list below.

> **Important:** results are only as local as the device running node-tester. If you run it on your Windows PC, you measured your PC's network. For phone-accurate results, run it in Termux on the phone.

## How core binaries are found
In order: `$SING_BOX_BIN` / `$XRAY_BIN` env vars → `./bin/sing-box(.exe)`, `./bin/xray(.exe)` → `PATH`.
If neither binary exists the server still runs and the UI works; every test simply reports `core binary not found`. `GET /api/health` reports what was found — check it first if all nodes fail the same way.

## Outputs (written to `outputs/` after every test)
`top_15_speedy_nodes.txt`, `all_working_base64.txt`, `speed_50_plus.txt`, `speed_40_50.txt`, `speed_30_40.txt`, `speed_20_30.txt`, `speed_under_20.txt` (base64, same scheme as tester.py), plus `singbox.json`, `clash.yaml`, `xray.json`, `raw_uris.txt`.

## Troubleshooting
| Symptom | Fix |
|---|---|
| Every node: `core binary not found` | Binaries missing/misnamed. Check `/api/health`, then re-check step 3 (Windows) or re-run `termux-setup.sh` (Android). Names must be exactly `sing-box` / `sing-box.exe` and `xray` / `xray.exe` inside `bin/`. |
| Page at localhost:3000 won't load | Server isn't running (start it and keep the terminal/Termux session open), or the port is taken — start with another port (`PORT=3001`). |
| Android: testing stops when screen turns off | `termux-wake-lock` + set Termux battery to Unrestricted (see Android Step 4). |
| All nodes `timeout` / `connect` on Android, but they work in your VPN app | Termux itself may be blocked by a VPN app running in "block connections without VPN" / always-on mode, or per-app routing excludes Termux. Temporarily disconnect the VPN or allow Termux in its split-tunnel settings. |
| Clipboard button does nothing | Browsers restrict clipboard reading; just long-press → Paste into the text box instead — same result. |
| Speeds look lower than tester.py's | Expected — tester.py inflated/deflated numbers by running 20 downloads at once. Stage 2 runs 3 at a time, so these numbers are closer to real single-node speed. |
| `EADDRINUSE` / port already in use | An old copy is still running. Close that terminal window (Windows) or `Ctrl+C` the old Termux session, or use another port. |

## Privacy
- Runs **100% locally**. Nothing is sent to any cloud service by node-tester itself.
- Subscription URLs are **private**: they're stored only in local `data/sources.json` (git-ignored), shown redacted in lists/logs, and only ever requested from the provider URL itself. Test nodes obviously connect to the node servers and to Cloudflare's latency/speed endpoints — that's the test.

## API (summary)
`GET /api/health` · `POST /api/parse` · `POST /api/fetch-sub {urls}` · `GET|POST /api/sources`, `DELETE /api/sources/:id` · `POST /api/test {rawInput, urls, settings}` → `jobId` · `GET /api/test/:id/events` (SSE) · `GET /api/test/:id/results` · `GET /sub/tested?target=` · `GET|POST /api/qr` · `GET /api/outputs/:file`

## Credits & licenses
- **node-tester** and **`src/vpnCore.js`** are MIT (see `LICENSE`). vpnCore comes from the author's own [URI-link-generator](https://github.com/riology/URI-link-generator) repo.
- **sing-box** (GPL-3.0) and **Xray-core** (MPL-2.0) are *separate standalone binaries* you download yourself (Windows guide step 3 / `termux-setup.sh`) — they are not bundled or linked into this code, and their own licenses apply to them.
- Runtime deps: express, qrcode, js-yaml, socks-proxy-agent (each under its own open-source license).

## Known limitations
- Speed numbers are still *relative* — your connection is shared during stage 2, just far less than in tester.py.
- Clipboard read in the phone browser needs a secure context / permission; on plain `http://localhost` it usually works, and there's a manual paste fallback.
- One core process is spawned per node test (simple and robust, not the fastest possible design for 1,000+ nodes).
