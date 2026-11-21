'use strict';
/**
 * tester.js — dual-core real node tester (logic ported from tester.py,
 * parser NOT ported: nodes come from vpnCore).
 *
 * Engine routing (by vpnCore compatibility flags):
 *  - sing-box: primary, supports every protocol incl. hysteria2/tuic.
 *  - xray: fallback/preferred for xray-compatible nodes when sing-box absent.
 * Per node: build a one-node core config with a SOCKS/mixed inbound on a
 * pooled local port, spawn the core, poll the port for readiness (no fixed
 * sleep), test through the SOCKS proxy, kill the core, clean up.
 *
 * Two-stage accuracy model (fixes tester.py running 20 x 5MB at once):
 *  Stage 1: latency for ALL nodes, bounded concurrency (default 10),
 *           GET http://cp.cloudflare.com/generate_204, timeout default 6s.
 *  Stage 2: speed ONLY for the top N by latency (default 50), LOW
 *           concurrency (default 3), download from speed.cloudflare.com.
 * Failures always carry a short reason string — nothing is swallowed.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const http = require('http');
const https = require('https');
const { spawn } = require('child_process');
const { EventEmitter } = require('events');
const { SocksProxyAgent } = require('socks-proxy-agent');
const core = require('./vpnCore');

const ROOT = path.join(__dirname, '..');

/* ------------------------------------------------------------------ */
/* Binary discovery                                                    */
/* ------------------------------------------------------------------ */
function isExecutable(p) {
  try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; }
}
function findInPath(name) {
  const dirs = (process.env.PATH || '').split(path.delimiter);
  for (const d of dirs) {
    if (!d) continue;
    const p = path.join(d, name);
    if (isExecutable(p)) return p;
  }
  return null;
}
function findBinaries() {
  const singBoxCandidates = [
    process.env.SING_BOX_BIN,
    path.join(ROOT, 'bin', 'sing-box'),
    path.join(ROOT, 'bin', 'sing-box.exe'),
  ].filter(Boolean);
  const xrayCandidates = [
    process.env.XRAY_BIN,
    path.join(ROOT, 'bin', 'xray'),
    path.join(ROOT, 'bin', 'xray.exe'),
  ].filter(Boolean);
  let singbox = singBoxCandidates.find(isExecutable) || findInPath('sing-box');
  let xray = xrayCandidates.find(isExecutable) || findInPath('xray');
  return { singbox: singbox || null, xray: xray || null };
}

/* ------------------------------------------------------------------ */
/* Per-node config builders                                            */
/* ------------------------------------------------------------------ */
function buildSingBoxConfig(node, localPort) {
  const profile = core.toSingBoxProfile([node]);
  const nodeOutbounds = (profile.outbounds || []).filter(
    (o) => !['selector', 'urltest', 'direct', 'block', 'dns'].includes(o.type)
  );
  if (!nodeOutbounds.length) throw new Error('vpnCore produced no sing-box outbound for this node');
  const nodeOut = nodeOutbounds[0];
  return {
    log: { disabled: true, level: 'error' },
    inbounds: [
      { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: localPort },
    ],
    outbounds: [nodeOut, { type: 'direct', tag: 'direct' }],
    route: { final: nodeOut.tag, auto_detect_interface: true },
  };
}

function buildXrayConfig(node, localPort) {
  if (!node.compatibility || !node.compatibility.xray) {
    throw new Error('node is not xray-compatible (sing-box only)');
  }
  const cfg = core.toXrayConfig([node]);
  const nodeOutbounds = (cfg.outbounds || []).filter((o) => !['freedom', 'blackhole'].includes(o.protocol));
  if (!nodeOutbounds.length) throw new Error('vpnCore produced no xray outbound for this node');
  return {
    log: { loglevel: 'none' },
    inbounds: [
      {
        tag: 'socks-in', port: localPort, listen: '127.0.0.1', protocol: 'socks',
        settings: { auth: 'noauth', udp: false },
      },
    ],
    outbounds: [...nodeOutbounds, { tag: 'direct', protocol: 'freedom', settings: {} }],
  };
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
function waitForPort(port, timeoutMs, isDead) {
  const start = Date.now();
  return new Promise((resolve) => {
    const attempt = () => {
      if (isDead && isDead()) return resolve(false);
      if (Date.now() - start > timeoutMs) return resolve(false);
      const sock = net.connect(port, '127.0.0.1');
      sock.once('connect', () => { sock.destroy(); resolve(true); });
      sock.once('error', () => { sock.destroy(); setTimeout(attempt, 100); });
    };
    attempt();
  });
}

function requestThroughSocks(urlStr, localPort, { timeoutMs = 6000, maxBytes = Infinity } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${localPort}`);
    const lib = u.protocol === 'https:' ? https : http;
    const started = Date.now();
    let bytes = 0;
    const req = lib.get(u, { agent, timeout: timeoutMs }, (res) => {
      res.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes >= maxBytes) req.destroy();
      });
      res.on('end', () => resolve({ status: res.statusCode, bytes, ms: Date.now() - started }));
      res.on('error', reject);
      res.on('aborted', () => resolve({ status: res.statusCode, bytes, ms: Date.now() - started }));
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', (e) => {
      // A destroy() after reaching maxBytes surfaces as an error on some
      // versions; if we already have the bytes we wanted, treat as success.
      if (bytes >= maxBytes && Number.isFinite(maxBytes)) {
        return resolve({ status: 200, bytes, ms: Date.now() - started });
      }
      reject(e);
    });
  });
}

function classifyError(e, phase) {
  const msg = String((e && e.message) || e || '').toLowerCase();
  if (msg.includes('timeout') || msg.includes('timed out') || msg.includes('aborted')) return 'timeout';
  if (msg.includes('tls') || msg.includes('ssl') || msg.includes('certificate')) return 'tls';
  if (msg.includes('core exited') || msg.includes('core-exit')) return 'core-exit';
  if (msg.includes('econnrefused') || msg.includes('connect')) return 'connect';
  if (msg.includes('socks')) return 'socks';
  return `${phase}-error: ${String((e && e.message) || e).slice(0, 80)}`;
}

/* ------------------------------------------------------------------ */
/* Concurrency pool                                                    */
/* ------------------------------------------------------------------ */
async function runPool(items, concurrency, worker) {
  const results = new Array(items.length);
  let idx = 0;
  async function next() {
    while (idx < items.length) {
      const cur = idx++;
      results[cur] = await worker(items[cur], cur);
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, items.length || 1)) }, next));
  return results;
}

/* ------------------------------------------------------------------ */
/* Tester                                                              */
/* ------------------------------------------------------------------ */
const DEFAULTS = {
  stage2Limit: 50,
  payloadBytes: 5 * 1024 * 1024,
  latencyConcurrency: 10,
  speedConcurrency: 3,
  timeoutMs: 6000,
  targetCount: 0, // 0 = test everything
  basePort: 20000,
};

class Tester extends EventEmitter {
  constructor() {
    super();
    this.binaries = findBinaries();
  }
  refreshBinaries() { this.binaries = findBinaries(); return this.binaries; }

  pickEngine(node) {
    const b = this.binaries;
    if (b.singbox && node.compatibility && node.compatibility.singbox) return { engine: 'sing-box', bin: b.singbox };
    if (b.xray && node.compatibility && node.compatibility.xray) return { engine: 'xray', bin: b.xray };
    if (b.singbox && node.compatibility && node.compatibility.xray) return { engine: 'xray-missing', bin: null };
    if (!b.singbox && !b.xray) return { engine: null, bin: null, reason: 'core binary not found' };
    return { engine: null, bin: null, reason: 'no compatible core binary for this protocol' };
  }

  async testOneThroughCore(node, localPort, settings, phase, url, maxBytes) {
    const picked = this.pickEngine(node);
    if (!picked.bin) throw new Error(picked.reason || 'core binary not found');
    const cfg = picked.engine === 'sing-box'
      ? buildSingBoxConfig(node, localPort)
      : buildXrayConfig(node, localPort);
    const tmpFile = path.join(os.tmpdir(), `node-tester-${process.pid}-${localPort}-${phase}.json`);
    fs.writeFileSync(tmpFile, JSON.stringify(cfg), 'utf8');
    const args = picked.engine === 'sing-box' ? ['run', '-c', tmpFile] : ['run', '-c', tmpFile];
    let proc = null;
    let exited = false;
    try {
      proc = spawn(picked.bin, args, { stdio: ['ignore', 'ignore', 'pipe'] });
      let stderr = '';
      if (proc.stderr) proc.stderr.on('data', (d) => { stderr = (stderr + d.toString()).slice(-500); });
      proc.on('exit', () => { exited = true; });
      const ready = await waitForPort(localPort, 6000, () => exited);
      if (!ready) {
        throw new Error(exited ? `core exited early${stderr ? `: ${stderr.trim().split('\n').pop().slice(0, 100)}` : ''}` : 'core port never opened (timeout)');
      }
      const out = await requestThroughSocks(url, localPort, { timeoutMs: settings.timeoutMs, maxBytes });
      return { ...out, engine: picked.engine };
    } finally {
      if (proc) { try { proc.kill('SIGTERM'); } catch {} }
      try { fs.unlinkSync(tmpFile); } catch {}
    }
  }

  /**
   * Test an array of vpnCore node objects.
   * onProgress({phase, done, total, passed}) is called as work proceeds.
   */
  async testNodes(nodes, settings = {}, onProgress = () => {}) {
    const s = { ...DEFAULTS, ...settings };
    this.refreshBinaries();
    const portPool = [];
    const maxConc = Math.max(s.latencyConcurrency, s.speedConcurrency);
    for (let i = 0; i < maxConc + 2; i++) portPool.push(s.basePort + i);
    const takePort = async () => {
      while (!portPool.length) await new Promise((r) => setTimeout(r, 50));
      return portPool.pop();
    };

    const results = nodes.map((n) => ({
      remark: n.remark, protocol: n.protocol, host: n.host, port: n.port,
      uri: n.normalizedUri || n.originalUri || '',
      latencyMs: null, mbps: 0, status: 'dead', error: '', engine: '',
    }));
    let passed = 0;
    let done1 = 0;

    /* ---- Stage 1: latency for all ---- */
    await runPool(nodes, s.latencyConcurrency, async (node, i) => {
      const r = results[i];
      if (s.targetCount > 0 && passed >= s.targetCount) {
        r.error = 'skipped: target count reached';
        done1++;
        onProgress({ phase: 'latency', done: done1, total: nodes.length, passed });
        return;
      }
      const port = await takePort();
      try {
        const out = await this.testOneThroughCore(node, port, s, 'latency', 'http://cp.cloudflare.com/generate_204', Infinity);
        r.engine = out.engine;
        if (out.status === 204 || out.status === 200) {
          r.latencyMs = Math.round(out.ms);
          r.status = 'alive';
          passed++;
        } else {
          r.error = `unexpected HTTP ${out.status} on latency check`;
        }
      } catch (e) {
        r.error = classifyError(e, 'latency');
        if (String(e.message || '').includes('core binary not found')) r.error = 'core binary not found';
        if (String(e.message || '').includes('core exited')) r.error = `core-exit: ${String(e.message).slice(0, 100)}`;
      } finally {
        portPool.push(port);
        done1++;
        onProgress({ phase: 'latency', done: done1, total: nodes.length, passed });
      }
    });

    /* ---- Stage 2: speed for top N by latency ---- */
    const aliveIdx = results
      .map((r, i) => (r.status === 'alive' ? i : -1))
      .filter((i) => i >= 0)
      .sort((a, b) => results[a].latencyMs - results[b].latencyMs)
      .slice(0, s.stage2Limit);
    let done2 = 0;
    await runPool(aliveIdx, s.speedConcurrency, async (nodeIdx) => {
      const node = nodes[nodeIdx];
      const r = results[nodeIdx];
      const port = await takePort();
      try {
        const url = `https://speed.cloudflare.com/__down?bytes=${s.payloadBytes}`;
        const speedSettings = { ...s, timeoutMs: Math.max(s.timeoutMs, 20000) };
        const out = await this.testOneThroughCore(node, port, speedSettings, 'speed', url, s.payloadBytes);
        r.engine = out.engine || r.engine;
        if (out.bytes > 0 && out.ms > 0) {
          r.mbps = Math.round(((out.bytes * 8) / (out.ms / 1000) / 1_000_000) * 100) / 100;
        } else {
          r.error = 'speed test returned no data';
        }
      } catch (e) {
        r.error = `speed: ${classifyError(e, 'speed')}`;
      } finally {
        portPool.push(port);
        done2++;
        onProgress({ phase: 'speed', done: done2, total: aliveIdx.length, passed });
      }
    });
    onProgress({ phase: 'done', done: results.length, total: results.length, passed });

    results.sort((a, b) => (b.mbps - a.mbps) || ((a.latencyMs ?? Infinity) - (b.latencyMs ?? Infinity)));
    return results;
  }
}

module.exports = { Tester, buildSingBoxConfig, buildXrayConfig, findBinaries, parseUserinfo: undefined, DEFAULTS };
