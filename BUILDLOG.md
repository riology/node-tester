# Build Log — node-tester

- Cloned riology/URI-link-generator (MIT) via git; copied src/vpnCore.js and LICENSE into this project.
- sing-box binary found in VM at ~/workspace/avx/toolchain/sing-box-check (used only for local config validation in tests, NOT shipped).
- Architecture: sources -> vpnCore -> dual-core tester (sing-box primary, Xray fallback) -> ready outputs + live /sub/tested.

## Results (2026-11-21, this VM, Node v24.22.1)
- npm install: 106 packages, OK.
- Clash YAML detection bug found in first test run (flow-style `- {name: …}` missed) — fixed in src/sources.js, re-ran.
- Upstream vpnCore bug found: `hy2://` short scheme was not stripped in parseHysteria2Uri, corrupting the password + normalizedUri. Patched locally in src/vpnCore.js (marked with a "node-tester patch" comment) + regression test added.
- npm test: **33 passed, 0 failed.**
  - vpnCore parse + compatibility flags for vless (ws/tls, reality), vmess, ss, trojan, hy2, tuic.
  - sources: base64 detection, Clash converter (snell skipped with warning), hy2 Clash conversion, userinfo + profile-title parsers.
  - config builders: sing-box configs for all 6 protocols; xray configs for the 4 xray-compatible ones; hy2/tuic correctly refused by xray builder.
  - outputs: base64 round-trips, singBoxJson parses, clashYaml contains proxies.
  - **Real core validation: `sing-box check` (AVX toolchain binary) accepted 6/6 generated protocol configs.**
  - Server smoke: /api/health 200; /api/fetch-sub against a local fixture subscription server parsed 7 fake nodes and returned subscription-userinfo + profile title.
  - Full /api/test job over 7 unreachable fake nodes: completed, all dead WITH reasons, outputs files written, /sub/tested served with headers.
- Extra real-core smoke (SING_BOX_BIN=AVX sing-box): Tester spawned the real sing-box, port polling worked, SOCKS request attempted; unreachable fake vless + hy2 nodes reported dead with reason `connect` (proves the spawn/test flow, not just the missing-binary path).
- Server boot smoke on port 3457: UI HTML served (Sources/Test/Ready-output sections present), /api/health reported the sing-box binary.
- UNVERIFIED: real latency/speed against live public nodes (fake nodes only, by design); Xray engine path (no xray binary in this VM — code path tested only via config builder + missing-binary handling); Termux/Android arm64 binary downloads in termux-setup.sh (script written, not run on Android); clipboard read on REYAD's phone browser; SSE UI in a real phone browser.
