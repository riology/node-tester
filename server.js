'use strict';
/**
 * node-tester server — runs 100% locally (Termux on the user's phone or a
 * desktop). Because it runs on the user's own network, subscription
 * fetching and node testing measure HIS real connection.
 *
 * Endpoints:
 *   GET  /api/health
 *   POST /api/parse            (generator-compatible: vpnCore processRawInput)
 *   POST /api/fetch-sub        {urls:[...]} (+ optional save:true)
 *   GET  /api/sources          saved subscription sources (redacted)
 *   POST /api/sources          {url, name}
 *   DELETE /api/sources/:id
 *   POST /api/test             {rawInput, urls, settings} -> {jobId}
 *   GET  /api/test/:jobId/events   SSE progress + done
 *   GET  /api/test/:jobId/results  JSON results + outputs
 *   GET  /sub/tested           live subscription of last completed job
 *   POST /api/qr  /  GET /api/qr?text=
 */
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const QRCode = require('qrcode');
const core = require('./src/vpnCore');
const sources = require('./src/sources');
const { Tester, findBinaries } = require('./src/tester');
const { writeOutputs } = require('./src/outputs');
const pkg = require('./package.json');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.text({ limit: '10mb', type: ['text/*'] }));
app.use(express.static(path.join(__dirname, 'public')));

const jobs = new Map(); // jobId -> {id,status,progress,results,outputs,settings,createdAt,clients:Set}
let lastTested = null; // {results, outputs, at}

function newJob(settings) {
  const id = crypto.randomBytes(6).toString('hex');
  const job = { id, status: 'running', progress: { phase: 'starting', done: 0, total: 0, passed: 0 }, results: null, outputs: null, written: [], settings, createdAt: new Date().toISOString(), clients: new Set() };
  jobs.set(id, job);
  return job;
}
function emit(job, event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of job.clients) { try { res.write(payload); } catch {} }
}

/* ---------------- health ---------------- */
app.get('/api/health', (req, res) => {
  const binaries = findBinaries();
  res.json({ ok: true, name: pkg.name, version: pkg.version, node: process.version, binaries, singbox: binaries.singbox, xray: binaries.xray });
});

/* ---------------- generator-compatible parse ---------------- */
app.post('/api/parse', (req, res) => {
  try {
    const { rawInput = '', targetCore = 'all', deduplicate = false, remarkPrefix = '', renumberRemarks = false } = req.body || {};
    const result = core.processRawInput(rawInput, { targetCore, deduplicate, remarkPrefix, renumberRemarks });
    res.json({ ok: true, ...result });
  } catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});

/* ---------------- sources ---------------- */
app.post('/api/fetch-sub', async (req, res) => {
  try {
    const urls = (req.body && req.body.urls) || [];
    if (!Array.isArray(urls) || !urls.length) return res.status(400).json({ ok: false, error: 'Provide urls: [...]' });
    const { sources: fetched, nodes } = await sources.fetchSubscriptions(urls);
    if (req.body.save) for (const u of urls) sources.addSavedSource(u, req.body.name || '');
    res.json({
      ok: true,
      sources: fetched.map((s) => ({ source: s.source, format: s.format, nodeCount: s.nodeCount, warnings: s.warnings, userinfo: s.userinfo, profileTitle: s.profileTitle, updateIntervalHours: s.updateIntervalHours, fetchError: s.fetchError || null })),
      nodeCount: nodes.length,
      nodes: nodes.map((n) => ({ remark: n.remark, protocol: n.protocol, host: n.host, port: n.port, uri: n.normalizedUri })),
    });
  } catch (e) { res.status(400).json({ ok: false, error: e.message }); }
});

app.get('/api/sources', (req, res) => res.json({ ok: true, sources: sources.publicSavedSources() }));
app.post('/api/sources', (req, res) => {
  const { url, name } = req.body || {};
  if (!url) return res.status(400).json({ ok: false, error: 'url required' });
  const entry = sources.addSavedSource(url, name || '');
  res.json({ ok: true, id: entry.id });
});
app.delete('/api/sources/:id', (req, res) => { sources.removeSavedSource(req.params.id); res.json({ ok: true }); });

/* ---------------- testing jobs ---------------- */
app.post('/api/test', async (req, res) => {
  const { rawInput = '', urls = [], useSavedSources = false, settings = {} } = req.body || {};
  const job = newJob(settings);
  res.json({ ok: true, jobId: job.id });

  (async () => {
    try {
      let nodes = [];
      const warnings = [];
      if (rawInput && String(rawInput).trim()) {
        const parsed = sources.parsePayload(String(rawInput));
        nodes.push(...parsed.nodes);
        warnings.push(...parsed.warnings);
      }
      let fetchUrls = [...urls];
      if (useSavedSources) fetchUrls.push(...sources.loadSavedSources().map((s) => s.url));
      if (fetchUrls.length) {
        const fetched = await sources.fetchSubscriptions(fetchUrls);
        nodes.push(...fetched.nodes);
        job.sourceStats = fetched.sources.map((s) => ({ source: s.source, nodeCount: s.nodeCount, format: s.format, userinfo: s.userinfo, profileTitle: s.profileTitle }));
      }
      // dedup across all inputs
      const seen = new Set();
      nodes = nodes.filter((n) => (seen.has(n.dedupKey) ? false : (seen.add(n.dedupKey), true)));
      job.totalNodes = nodes.length;
      job.warnings = warnings;
      emit(job, 'progress', { ...job.progress, total: nodes.length });

      if (!nodes.length) {
        job.status = 'done';
        job.results = [];
        const w = writeOutputs([]);
        job.outputs = w.outputs; job.written = w.written;
        lastTested = { results: [], outputs: w.outputs, at: new Date().toISOString() };
        emit(job, 'done', { results: [], outputs: w.outputs, written: w.written });
        return;
      }

      const tester = new Tester();
      const results = await tester.testNodes(nodes, settings, (p) => {
        job.progress = p;
        emit(job, 'progress', p);
      });
      job.results = results;
      const w = writeOutputs(results);
      job.outputs = w.outputs; job.written = w.written; job.copiedToDownloads = w.copiedToDownloads;
      lastTested = { results, outputs: w.outputs, at: new Date().toISOString() };
      job.status = 'done';
      emit(job, 'done', { results, outputs: w.outputs, written: w.written, copiedToDownloads: w.copiedToDownloads });
    } catch (e) {
      job.status = 'error';
      job.error = e.message;
      emit(job, 'error', { error: e.message });
    }
  })();
});

app.get('/api/test/:jobId/events', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ ok: false, error: 'job not found' });
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.write(`event: progress\ndata: ${JSON.stringify(job.progress)}\n\n`);
  if (job.status === 'done') {
    res.write(`event: done\ndata: ${JSON.stringify({ results: job.results, outputs: job.outputs, written: job.written })}\n\n`);
    return res.end();
  }
  if (job.status === 'error') {
    res.write(`event: error\ndata: ${JSON.stringify({ error: job.error })}\n\n`);
    return res.end();
  }
  job.clients.add(res);
  req.on('close', () => job.clients.delete(res));
});

app.get('/api/test/:jobId/results', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ ok: false, error: 'job not found' });
  res.json({ ok: true, id: job.id, status: job.status, progress: job.progress, totalNodes: job.totalNodes || 0, sourceStats: job.sourceStats || [], warnings: job.warnings || [], results: job.results, outputs: job.outputs, written: job.written || [], error: job.error || null });
});

/* ---------------- live tested subscription ---------------- */
app.get('/sub/tested', (req, res) => {
  if (!lastTested) return res.status(404).send('No completed test job yet');
  const target = (req.query.target || req.query.format || '').toLowerCase();
  const outputs = lastTested.outputs;
  const titleB64 = core.safeBase64Encode('Node Tester — Tested Nodes');
  res.setHeader('Profile-Title', `base64:${titleB64}`);
  res.setHeader('Profile-Update-Interval', '12');
  res.setHeader('Subscription-Userinfo', 'upload=0; download=0; total=10737418240000; expire=2145916800');
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (target === 'clash') { res.setHeader('Content-Type', 'text/yaml; charset=utf-8'); return res.send(outputs.clashYaml); }
  if (target === 'singbox-json') { res.setHeader('Content-Type', 'application/json; charset=utf-8'); return res.send(outputs.singBoxJson); }
  if (target === 'xray-json') { res.setHeader('Content-Type', 'application/json; charset=utf-8'); return res.send(outputs.xrayJson); }
  if (target === 'raw') { res.setHeader('Content-Type', 'text/plain; charset=utf-8'); return res.send(outputs.rawUris); }
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  return res.send(outputs.base64);
});

/* ---------------- QR ---------------- */
async function qrHandler(text, res) {
  if (!text) return res.status(400).json({ ok: false, error: 'Missing text' });
  const svg = await QRCode.toString(text, { type: 'svg', margin: 1, width: 240 });
  res.json({ ok: true, svg });
}
app.post('/api/qr', async (req, res) => { try { await qrHandler((req.body || {}).text || '', res); } catch (e) { res.status(400).json({ ok: false, error: e.message }); } });
app.get('/api/qr', async (req, res) => { try { await qrHandler(req.query.text || '', res); } catch (e) { res.status(400).json({ ok: false, error: e.message }); } });

/* ---------------- downloads of ready output files ---------------- */
app.get('/api/outputs/:file', (req, res) => {
  const safe = path.basename(req.params.file);
  const file = path.join(__dirname, 'outputs', safe);
  res.download(file, safe, (err) => { if (err && !res.headersSent) res.status(404).json({ ok: false, error: 'file not found' }); });
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    const b = findBinaries();
    console.log(`node-tester running at http://localhost:${PORT}`);
    console.log(`cores: sing-box=${b.singbox || 'NOT FOUND'} xray=${b.xray || 'NOT FOUND'}`);
  });
}

module.exports = app;
module.exports._jobs = jobs;
module.exports._setLastTested = (v) => { lastTested = v; };
