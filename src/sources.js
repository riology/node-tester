'use strict';
/**
 * sources.js — input sources for node-tester.
 *
 * (a) raw pasted text (raw URIs / base64 / sing-box JSON / Xray JSON / Clash YAML)
 * (b) subscription URL fetcher — runs server-side. The server runs locally on
 *     the user's own device/network (e.g. Termux on his phone), so fetching
 *     and later testing both use HIS network, not a cloud server.
 *
 * Parsing/normalisation is delegated to vpnCore (from URI-link-generator,
 * MIT) via processRawInput for everything it handles. Clash/Mihomo YAML is
 * NOT handled by vpnCore, so this module converts Clash `proxies:` entries
 * into share URIs first and then lets vpnCore parse/normalise them.
 *
 * PRIVACY: subscription URLs are private. They are stored only in the local
 * data/sources.json file, never printed in full to logs, and are only ever
 * requested from the provider URL itself.
 */
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const core = require('./vpnCore');

const DATA_DIR = path.join(__dirname, '..', 'data');
const SOURCES_FILE = path.join(DATA_DIR, 'sources.json');

/* ------------------------------------------------------------------ */
/* subscription-userinfo / profile headers                             */
/* ------------------------------------------------------------------ */
function parseUserinfo(header) {
  if (!header || typeof header !== 'string') return null;
  const out = {};
  for (const part of header.split(';')) {
    const [k, v] = part.split('=').map((s) => (s || '').trim());
    if (!k) continue;
    const n = Number(v);
    out[k] = Number.isFinite(n) ? n : v;
  }
  if (typeof out.expire === 'number' && out.expire > 0) {
    out.expireDate = new Date(out.expire * 1000).toISOString();
  }
  if (typeof out.upload === 'number' && typeof out.download === 'number' && typeof out.total === 'number' && out.total > 0) {
    out.used = out.upload + out.download;
    out.usedPercent = Math.round(((out.upload + out.download) / out.total) * 1000) / 10;
  }
  return out;
}

function parseProfileTitle(header) {
  if (!header) return '';
  let h = String(header).trim();
  if (h.startsWith('base64:')) {
    const decoded = core.safeBase64Decode(h.slice('base64:'.length));
    return decoded || h;
  }
  try { return decodeURIComponent(h); } catch { return h; }
}

/* ------------------------------------------------------------------ */
/* Clash / Mihomo YAML -> share URIs                                   */
/* ------------------------------------------------------------------ */
function q(params) {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue;
    usp.set(k, String(v));
  }
  const s = usp.toString();
  return s ? `?${s}` : '';
}
function hostPort(p) {
  const server = String(p.server || '');
  return server.includes(':') && !server.startsWith('[') ? `[${server}]` : server;
}
function transportParams(p) {
  const net = (p.network || 'tcp').toLowerCase();
  const params = { type: net };
  if (net === 'ws' && p['ws-opts']) {
    params.path = p['ws-opts'].path || '/';
    const h = p['ws-opts'].headers && (p['ws-opts'].headers.Host || p['ws-opts'].headers.host);
    if (h) params.host = h;
  }
  if (net === 'grpc' && p['grpc-opts']) {
    params.serviceName = p['grpc-opts']['grpc-service-name'] || '';
  }
  if ((net === 'h2' || net === 'http') && p['h2-opts']) {
    params.path = (p['h2-opts'].path && p['h2-opts'].path[0]) || '/';
    const h = p['h2-opts'].host && p['h2-opts'].host[0];
    if (h) params.host = h;
  }
  return params;
}
function tlsParams(p) {
  const params = {};
  const reality = p['reality-opts'];
  if (reality) {
    params.security = 'reality';
    params.pbk = reality['public-key'] || '';
    params.sid = reality['short-id'] || '';
  } else if (p.tls) {
    params.security = 'tls';
  } else {
    params.security = 'none';
  }
  params.sni = p.servername || p.sni || '';
  params.fp = p['client-fingerprint'] || 'chrome';
  if (p.alpn) params.alpn = Array.isArray(p.alpn) ? p.alpn.join(',') : p.alpn;
  if (p['skip-cert-verify']) params.insecure = '1';
  return params;
}

function clashProxyToUri(p) {
  const name = encodeURIComponent(p.name || `${p.type}-${p.server}:${p.port}`);
  const hp = `${hostPort(p)}:${p.port}`;
  switch ((p.type || '').toLowerCase()) {
    case 'vless': {
      const params = { encryption: 'none', flow: p.flow || '', ...tlsParams(p), ...transportParams(p) };
      if (params.security === 'reality') { /* keep */ }
      return `vless://${p.uuid}@${hp}${q(params)}#${name}`;
    }
    case 'vmess': {
      const j = {
        v: '2', ps: p.name || 'vmess', add: p.server, port: String(p.port), id: p.uuid,
        aid: String(p.alterId || 0), scy: p.cipher || 'auto', net: p.network || 'tcp',
        type: 'none', host: (p['ws-opts'] && p['ws-opts'].headers && p['ws-opts'].headers.Host) || '',
        path: (p['ws-opts'] && p['ws-opts'].path) || (p['grpc-opts'] ? '' : ''),
        tls: p.tls ? 'tls' : '', sni: p.servername || p.sni || '',
      };
      if ((p.network || '') === 'grpc' && p['grpc-opts']) j.path = p['grpc-opts']['grpc-service-name'] || '';
      return `vmess://${core.safeBase64Encode(JSON.stringify(j))}`;
    }
    case 'trojan': {
      const params = { ...tlsParams(p), ...transportParams(p) };
      if (!p.tls && !p['reality-opts']) params.security = 'tls';
      return `trojan://${encodeURIComponent(p.password || '')}@${hp}${q(params)}#${name}`;
    }
    case 'ss':
    case 'shadowsocks': {
      const userinfo = core.safeBase64Encode(`${p.cipher}:${p.password || ''}`);
      let uri = `ss://${userinfo}@${hp}#${name}`;
      if (p.plugin) return { uri: null, warning: `ss node "${p.name || hp}" skipped: plugin "${p.plugin}" not supported` };
      return uri;
    }
    case 'hysteria2':
    case 'hy2': {
      const params = { sni: p.sni || p.servername || '', insecure: p['skip-cert-verify'] ? '1' : '', obfs: p.obfs || '', 'obfs-password': p['obfs-password'] || '', alpn: Array.isArray(p.alpn) ? p.alpn.join(',') : p.alpn || '' };
      return `hy2://${encodeURIComponent(p.password || p.auth || '')}@${hp}${q(params)}#${name}`;
    }
    case 'tuic': {
      const params = { sni: p.sni || p.servername || '', congestion_control: p['congestion-controller'] || 'bbr', udp_relay_mode: p['udp-relay-mode'] || 'native', alpn: Array.isArray(p.alpn) ? p.alpn.join(',') : p.alpn || '', allow_insecure: p['skip-cert-verify'] ? '1' : '' };
      return `tuic://${p.uuid}:${encodeURIComponent(p.password || '')}@${hp}${q(params)}#${name}`;
    }
    default:
      return { uri: null, warning: `Unsupported Clash proxy type "${p.type}" for "${p.name || hp}" — skipped` };
  }
}

function parseClashYaml(text) {
  const warnings = [];
  let doc;
  try { doc = yaml.load(text); } catch (e) { return { uris: [], warnings: [`Clash YAML parse failed: ${e.message}`], isClash: false }; }
  if (!doc || !Array.isArray(doc.proxies)) return { uris: [], warnings, isClash: false };
  const uris = [];
  for (const p of doc.proxies) {
    const r = clashProxyToUri(p);
    if (typeof r === 'string') uris.push(r);
    else if (r && r.warning) warnings.push(r.warning);
  }
  return { uris, warnings, isClash: true };
}

function looksLikeClashYaml(text) {
  return /(^|\n)\s*proxies\s*:/.test(text) && /(^|\n)\s*-\s*\{?\s*name\s*:/.test(text);
}

/* ------------------------------------------------------------------ */
/* Unified payload parsing                                             */
/* ------------------------------------------------------------------ */
/**
 * Parse any supported payload text into vpnCore nodes.
 * Returns { nodes, warnings, format, stats, errors }
 */
function parsePayload(text) {
  const warnings = [];
  if (!text || !String(text).trim()) return { nodes: [], warnings, format: 'empty', stats: null, errors: [] };
  const raw = String(text);
  if (looksLikeClashYaml(raw)) {
    const { uris, warnings: w, isClash } = parseClashYaml(raw);
    warnings.push(...w);
    if (isClash) {
      const res = core.processRawInput(uris.join('\n'), { deduplicate: true });
      return { nodes: res.nodes, warnings, format: 'clash-yaml', stats: res.stats, errors: res.errors };
    }
  }
  const res = core.processRawInput(raw, { deduplicate: true });
  const format = res.stats ? res.stats.inputType : 'raw'; // raw | base64 | json | mixed
  return { nodes: res.nodes, warnings, format, stats: res.stats, errors: res.errors };
}

/* ------------------------------------------------------------------ */
/* Subscription URL fetching                                           */
/* ------------------------------------------------------------------ */
function redactUrl(u) {
  try {
    const url = new URL(u);
    return `${url.protocol}//${url.host}/…${url.pathname.slice(-4)}`;
  } catch { return '(invalid url)'; }
}

async function fetchSubscription(url, opts = {}) {
  const timeoutMs = opts.timeoutMs || 20000;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(url, {
      redirect: 'follow',
      signal: ctrl.signal,
      headers: {
        'User-Agent': opts.userAgent || 'sing-box/1.11 node-tester/1.0',
        Accept: '*/*',
      },
    });
  } finally { clearTimeout(t); }
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching subscription`);
  const text = await res.text();
  if (text.length > 15 * 1024 * 1024) throw new Error('Subscription payload too large (>15MB)');
  const parsed = parsePayload(text);
  return {
    source: redactUrl(url),
    format: parsed.format,
    nodes: parsed.nodes,
    nodeCount: parsed.nodes.length,
    warnings: parsed.warnings,
    errors: parsed.errors,
    userinfo: parseUserinfo(res.headers.get('subscription-userinfo')),
    profileTitle: parseProfileTitle(res.headers.get('profile-title')) || '',
    updateIntervalHours: Number(res.headers.get('profile-update-interval')) || null,
  };
}

async function fetchSubscriptions(urls, opts = {}) {
  const results = [];
  const allNodes = [];
  const seen = new Set();
  for (const url of urls || []) {
    if (!url || !String(url).trim()) continue;
    try {
      const r = await fetchSubscription(String(url).trim(), opts);
      results.push(r);
      for (const n of r.nodes) {
        if (!seen.has(n.dedupKey)) { seen.add(n.dedupKey); allNodes.push(n); }
      }
    } catch (e) {
      results.push({ source: redactUrl(String(url)), format: 'error', nodes: [], nodeCount: 0, warnings: [], errors: [{ raw: e.message }], userinfo: null, profileTitle: '', fetchError: e.message });
    }
  }
  return { sources: results, nodes: allNodes };
}

/* ------------------------------------------------------------------ */
/* Saved sources (local only)                                          */
/* ------------------------------------------------------------------ */
function loadSavedSources() {
  try {
    if (!fs.existsSync(SOURCES_FILE)) return [];
    const arr = JSON.parse(fs.readFileSync(SOURCES_FILE, 'utf8'));
    return Array.isArray(arr) ? arr : [];
  } catch { return []; }
}
function saveSavedSources(list) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(SOURCES_FILE, JSON.stringify(list, null, 2), 'utf8');
}
function addSavedSource(url, name) {
  const list = loadSavedSources();
  const existing = list.find((s) => s.url === url);
  if (existing) { if (name) existing.name = name; saveSavedSources(list); return existing; }
  const entry = { id: `src-${Date.now().toString(36)}`, url, name: name || '', addedAt: new Date().toISOString() };
  list.push(entry);
  saveSavedSources(list);
  return entry;
}
function removeSavedSource(id) {
  const list = loadSavedSources().filter((s) => s.id !== id);
  saveSavedSources(list);
  return list;
}
function publicSavedSources() {
  // Never hand the full URL back in list responses beyond the owner UI's own
  // add-flow; list shows a redacted form.
  return loadSavedSources().map((s) => ({ id: s.id, name: s.name, source: redactUrl(s.url), addedAt: s.addedAt }));
}

module.exports = {
  parseUserinfo,
  parseProfileTitle,
  parseClashYaml,
  clashProxyToUri,
  looksLikeClashYaml,
  parsePayload,
  fetchSubscription,
  fetchSubscriptions,
  redactUrl,
  loadSavedSources,
  addSavedSource,
  removeSavedSource,
  publicSavedSources,
};
