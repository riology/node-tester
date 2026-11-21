'use strict';
/**
 * outputs.js — turn tested results into ready-to-use files/subscriptions.
 * Bracket scheme and base64 file format match tester.py:
 *   top_15_speedy_nodes.txt, speed_50_plus.txt, speed_40_50.txt,
 *   speed_30_40.txt, speed_20_30.txt, speed_under_20.txt
 * plus all_working_base64.txt, singbox.json, clash.yaml, xray.json.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const core = require('./vpnCore');

const OUTPUT_DIR = path.join(__dirname, '..', 'outputs');

function b64(text) { return core.safeBase64Encode(text); }

/**
 * results: tester results (alive ones are used), expected pre-sorted by Mbps.
 */
function computeOutputs(results) {
  const working = (results || []).filter((r) => r.status === 'alive' && r.uri);
  const uris = working.map((r) => r.uri);
  const rawUris = uris.join('\n');
  const processed = rawUris ? core.processRawInput(rawUris, { deduplicate: true }) : null;
  const outputs = {
    rawUris,
    base64: rawUris ? b64(rawUris) : '',
    singBoxJson: processed ? processed.outputs.singBoxJson : '',
    xrayJson: processed ? processed.outputs.xrayJson : '',
    clashYaml: processed ? processed.outputs.clashYaml : '',
    top15Base64: uris.slice(0, 15).length ? b64(uris.slice(0, 15).join('\n')) : '',
  };
  const brackets = { '50_plus': [], '40_50': [], '30_40': [], '20_30': [], 'under_20': [] };
  for (const r of working) {
    if (r.mbps >= 50) brackets['50_plus'].push(r.uri);
    else if (r.mbps >= 40) brackets['40_50'].push(r.uri);
    else if (r.mbps >= 30) brackets['30_40'].push(r.uri);
    else if (r.mbps >= 20) brackets['20_30'].push(r.uri);
    else brackets['under_20'].push(r.uri);
  }
  outputs.brackets = brackets;
  outputs.workingCount = working.length;
  return outputs;
}

const FILE_MAP = (outputs) => ({
  'top_15_speedy_nodes.txt': outputs.top15Base64,
  'all_working_base64.txt': outputs.base64,
  'speed_50_plus.txt': outputs.brackets['50_plus'].length ? b64(outputs.brackets['50_plus'].join('\n')) : '',
  'speed_40_50.txt': outputs.brackets['40_50'].length ? b64(outputs.brackets['40_50'].join('\n')) : '',
  'speed_30_40.txt': outputs.brackets['30_40'].length ? b64(outputs.brackets['30_40'].join('\n')) : '',
  'speed_20_30.txt': outputs.brackets['20_30'].length ? b64(outputs.brackets['20_30'].join('\n')) : '',
  'speed_under_20.txt': outputs.brackets['under_20'].length ? b64(outputs.brackets['under_20'].join('\n')) : '',
  'singbox.json': outputs.singBoxJson,
  'clash.yaml': outputs.clashYaml,
  'xray.json': outputs.xrayJson,
  'raw_uris.txt': outputs.rawUris,
});

function writeOutputs(results, outDir = OUTPUT_DIR) {
  const outputs = computeOutputs(results);
  const files = FILE_MAP(outputs);
  fs.mkdirSync(outDir, { recursive: true });
  const written = [];
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(outDir, name), content || '', 'utf8');
    written.push(name);
  }
  // Termux shared storage: if ~/storage/downloads exists, also copy there so
  // the user can grab files from any file manager — no manual moving.
  let copiedToDownloads = false;
  try {
    const dl = path.join(os.homedir(), 'storage', 'downloads', 'node-tester');
    if (fs.existsSync(path.join(os.homedir(), 'storage', 'downloads'))) {
      fs.mkdirSync(dl, { recursive: true });
      for (const name of written) fs.copyFileSync(path.join(outDir, name), path.join(dl, name));
      copiedToDownloads = true;
    }
  } catch { /* guarded: never fail the job over the copy */ }
  return { outputs, written, copiedToDownloads };
}

module.exports = { computeOutputs, writeOutputs, OUTPUT_DIR };
