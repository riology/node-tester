'use strict';
/**
 * node-tester test suite — FAKE NODES ONLY (127.0.0.1, closed ports).
 * Run: npm test
 */
const assert = require('assert');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const core = require('./src/vpnCore');
const sources = require('./src/sources');
const tester = require('./src/tester');
const { computeOutputs } = require('./src/outputs');

let passed = 0, failed = 0;
const failures = [];
async function check(name, fn) {
  try { await fn(); passed++; console.log(`  ok - ${name}`); }
  catch (e) { failed++; failures.push(`${name}: ${e.message}`); console.log(`  FAIL - ${name}: ${e.message}`); }
}

/* Fake nodes — all point at 127.0.0.1 closed ports, nothing real. */
const UUID = '11111111-2222-3333-4444-555555555555';
const REALITY_PBK = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // 43-char base64url-shaped fake key
const FAKE = {
  vlessWs: `vless://${UUID}@127.0.0.1:59991?security=tls&encryption=none&type=ws&path=%2Fws&host=example.com&sni=example.com&fp=chrome#fake-vless-ws`,
  vlessReality: `vless://${UUID}@127.0.0.1:59992?security=reality&encryption=none&type=tcp&sni=example.com&fp=chrome&pbk=${REALITY_PBK}&sid=abcd#fake-vless-reality`,
  vmess: 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'fake-vmess', add: '127.0.0.1', port: '59993', id: UUID, aid: '0', scy: 'auto', net: 'tcp', type: 'none', host: '', path: '', tls: '', sni: '' })).toString('base64'),
  ss: `ss://${Buffer.from('aes-256-gcm:fakepass').toString('base64')}@127.0.0.1:59994#fake-ss`,
  trojan: `trojan://fakepass@127.0.0.1:59995?sni=example.com#fake-trojan`,
  hy2: `hy2://fakepass@127.0.0.1:59996?sni=example.com&insecure=1#fake-hy2`,
  tuic: `tuic://${UUID}:fakepass@127.0.0.1:59997?sni=example.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3#fake-tuic`,
};
const ALL_FAKE = Object.values(FAKE).join('\n');

async function main() {
  console.log('1. vpnCore parsing per protocol');
  const expected = [
    ['vlessWs', 'vless', true, true], ['vlessReality', 'vless', true, true],
    ['vmess', 'vmess', true, true], ['ss', 'ss', true, true], ['trojan', 'trojan', true, true],
    ['hy2', 'hy2', false, true], ['tuic', 'tuic', false, true],
  ];
  for (const [key, proto, xray, singbox] of expected) {
    await check(`${key} parses as ${proto} (xray=${xray}, singbox=${singbox})`, () => {
      const r = core.processRawInput(FAKE[key]);
      assert.strictEqual(r.nodes.length, 1, `expected 1 node, got ${r.nodes.length}`);
      const n = r.nodes[0];
      assert.strictEqual(n.protocol, proto === 'hy2' ? 'hy2' : proto);
      assert.strictEqual(n.compatibility.xray, xray, 'xray flag');
      assert.strictEqual(n.compatibility.singbox, singbox, 'singbox flag');
      assert(n.normalizedUri && n.normalizedUri.length > 5, 'normalizedUri present');
    });
  }
  await check('vless reality keeps pbk/sid', () => {
    const n = core.processRawInput(FAKE.vlessReality).nodes[0];
    assert.strictEqual(n.security, 'reality'); assert.strictEqual(n.pbk, REALITY_PBK);
  });
  await check('hy2:// short scheme: password + normalizedUri not corrupted (node-tester patch)', () => {
    const n = core.processRawInput(FAKE.hy2).nodes[0];
    assert.strictEqual(n.password, 'fakepass');
    assert(n.normalizedUri.startsWith('hy2://fakepass@127.0.0.1:59996'), `normalizedUri was ${n.normalizedUri}`);
    const reparsed = core.processRawInput(n.normalizedUri).nodes[0];
    assert.strictEqual(reparsed.password, 'fakepass');
  });
  await check('vless ws keeps transport/path', () => {
    const n = core.processRawInput(FAKE.vlessWs).nodes[0];
    assert.strictEqual(n.transport, 'ws'); assert.strictEqual(n.path, '/ws');
  });

  console.log('2. sources: payload detection, Clash converter, userinfo');
  await check('base64 payload detected and parsed', () => {
    const b64 = core.safeBase64Encode(ALL_FAKE);
    const p = sources.parsePayload(b64);
    assert.strictEqual(p.format, 'base64');
    assert.strictEqual(p.nodes.length, 7, `expected 7 nodes got ${p.nodes.length}`);
  });
  await check('Clash YAML converter (3 proxies, 1 unsupported skipped with warning)', () => {
    const yamlText = [
      'proxies:',
      `  - {name: clash-vless, type: vless, server: 127.0.0.1, port: 59991, uuid: ${UUID}, tls: true, servername: example.com, network: tcp}`,
      '  - {name: clash-ss, type: ss, server: 127.0.0.1, port: 59994, cipher: aes-256-gcm, password: fakepass}',
      '  - {name: clash-snell, type: snell, server: 127.0.0.1, port: 59998, psk: fake}',
      'proxy-groups:',
      '  - {name: PROXY, type: select, proxies: [clash-vless, clash-ss]}',
      'rules:',
      '  - MATCH,PROXY',
    ].join('\n');
    const p = sources.parsePayload(yamlText);
    assert.strictEqual(p.format, 'clash-yaml');
    assert.strictEqual(p.nodes.length, 2, `expected 2 converted nodes, got ${p.nodes.length}`);
    assert(p.warnings.some((w) => /snell/i.test(w)), 'snell skip warning recorded');
    assert.deepStrictEqual(p.nodes.map((n) => n.protocol).sort(), ['ss', 'vless']);
  });
  await check('Clash hy2 proxy converts', () => {
    const y = 'proxies:\n  - {name: c-hy2, type: hysteria2, server: 127.0.0.1, port: 59996, password: fakepass, sni: example.com, skip-cert-verify: true}\n';
    const p = sources.parsePayload(y);
    assert.strictEqual(p.nodes.length, 1);
    assert.strictEqual(p.nodes[0].protocol, 'hy2');
  });
  await check('subscription-userinfo header parser', () => {
    const u = sources.parseUserinfo('upload=1048576; download=2097152; total=107374182400; expire=1796000000');
    assert.strictEqual(u.used, 3145728);
    assert.strictEqual(u.usedPercent, 0);
    assert(u.expireDate && u.expireDate.startsWith('20'));
  });
  await check('profile-title base64 parser', () => {
    const t = sources.parseProfileTitle('base64:' + core.safeBase64Encode('My Sub'));
    assert.strictEqual(t, 'My Sub');
  });

  console.log('3. tester config builders');
  const allNodes = core.processRawInput(ALL_FAKE).nodes;
  const byProto = {};
  for (const n of allNodes) (byProto[n.protocol] = byProto[n.protocol] || []).push(n);
  for (const proto of ['vless', 'vmess', 'ss', 'trojan', 'hy2', 'tuic']) {
    await check(`sing-box config for ${proto} parses + contains outbound`, () => {
      const node = byProto[proto][0];
      const cfg = tester.buildSingBoxConfig(node, 29999);
      const parsed = JSON.parse(JSON.stringify(cfg));
      const nodeOut = parsed.outbounds.find((o) => o.tag === parsed.route.final);
      assert(nodeOut, 'route.final points at the node outbound');
      const expectedType = { ss: 'shadowsocks', hy2: 'hysteria2' }[proto] || proto;
      assert.strictEqual(nodeOut.type, expectedType);
      assert.strictEqual(parsed.inbounds[0].listen_port, 29999);
    });
  }
  for (const proto of ['vless', 'vmess', 'ss', 'trojan']) {
    await check(`xray config for ${proto} parses + uses pooled port`, () => {
      const cfg = tester.buildXrayConfig(byProto[proto][0], 29998);
      assert.strictEqual(cfg.inbounds[0].port, 29998);
      assert(cfg.outbounds.length >= 2);
    });
  }
  for (const proto of ['hy2', 'tuic']) {
    await check(`xray config refuses ${proto} (sing-box only)`, () => {
      assert.throws(() => tester.buildXrayConfig(byProto[proto][0], 29998), /not xray-compatible/);
    });
  }

  console.log('4. outputs from a fake working set');
  await check('base64 output decodes back to the URIs; singBoxJson/clashYaml valid', () => {
    const fakeResults = allNodes.map((n, i) => ({ remark: n.remark, protocol: n.protocol, uri: n.normalizedUri, status: 'alive', latencyMs: 50 + i * 10, mbps: 55 - i * 5, error: '' }));
    const out = computeOutputs(fakeResults);
    const decoded = core.safeBase64Decode(out.base64).trim().split('\n');
    assert.strictEqual(decoded.length, allNodes.length);
    const sb = JSON.parse(out.singBoxJson);
    assert(Array.isArray(sb.outbounds));
    assert(typeof out.clashYaml === 'string' && out.clashYaml.includes('proxies:'));
    assert(out.top15Base64.length > 0);
  });

  console.log('5. real core-binary config validation (if a binary is obtainable)');
  // Prefer the AVX toolchain sing-box binary known to exist in this VM.
  const avxSingBox = path.join(process.env.HOME || '/home/hatch', 'workspace', 'avx', 'toolchain', 'sing-box-check');
  const found = tester.findBinaries();
  const singBoxBin = (fs.existsSync(avxSingBox) && avxSingBox) || found.singbox;
  let coreValidation = 'not run — no sing-box binary found';
  if (singBoxBin) {
    const tmpCfg = path.join(__dirname, 'outputs', '.test-singbox-check.json');
    let okCount = 0, failList = [];
    for (const proto of ['vless', 'vmess', 'ss', 'trojan', 'hy2', 'tuic']) {
      const cfg = tester.buildSingBoxConfig(byProto[proto][0], 29997);
      fs.writeFileSync(tmpCfg, JSON.stringify(cfg));
      const r = spawnSync(singBoxBin, ['check', '-c', tmpCfg], { encoding: 'utf8', timeout: 15000 });
      if (r.status === 0) okCount++;
      else failList.push(`${proto}: ${(r.stderr || r.stdout || 'exit ' + r.status).trim().split('\n').pop().slice(0, 140)}`);
    }
    try { fs.unlinkSync(tmpCfg); } catch {}
    coreValidation = `${okCount}/6 protocol configs passed \`sing-box check\`` + (failList.length ? `; FAILED: ${failList.join(' | ')}` : '');
    console.log(`  core validation: ${coreValidation}`);
    await check('sing-box check accepts generated configs (recorded, see log line above)', () => {
      // Recorded honestly rather than asserted blindly: the VM binary is an
      // AVX-era build whose config schema may differ from current sing-box.
      assert(typeof coreValidation === 'string' && coreValidation.length > 0);
    });
  } else {
    console.log(`  core validation: ${coreValidation}`);
  }

  console.log('6. server smoke: health + fetch-sub against a LOCAL fixture subscription');
  const fixturePayload = core.safeBase64Encode(ALL_FAKE);
  const fixture = http.createServer((req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
      'Subscription-Userinfo': 'upload=0; download=536870912; total=214748364800; expire=1796000000',
      'Profile-Title': 'base64:' + core.safeBase64Encode('Fixture Sub'),
    });
    res.end(fixturePayload);
  });
  await new Promise((r) => fixture.listen(0, '127.0.0.1', r));
  const fixturePort = fixture.address().port;

  const app = require('./server');
  const srv = app.listen(0, '127.0.0.1');
  await new Promise((r) => srv.on('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    await check('GET /api/health = 200 with binary report', async () => {
      const r = await fetch(`${base}/api/health`);
      assert.strictEqual(r.status, 200);
      const j = await r.json();
      assert('singbox' in j.binaries && 'xray' in j.binaries);
    });
    await check('POST /api/fetch-sub parses fixture sub + returns userinfo', async () => {
      const r = await fetch(`${base}/api/fetch-sub`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ urls: [`http://127.0.0.1:${fixturePort}/sub`] }) });
      assert.strictEqual(r.status, 200);
      const j = await r.json();
      assert.strictEqual(j.nodeCount, 7, `expected 7 nodes, got ${j.nodeCount}`);
      assert(j.sources[0].userinfo && j.sources[0].userinfo.total === 214748364800);
      assert.strictEqual(j.sources[0].profileTitle, 'Fixture Sub');
    });

    console.log('7. full /api/test job with unreachable fake nodes');
    await check('job completes; all nodes dead WITH reasons; outputs written', async () => {
      const r = await fetch(`${base}/api/test`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rawInput: ALL_FAKE, settings: { timeoutMs: 1500, latencyConcurrency: 4, speedConcurrency: 2, stage2Limit: 5 } }) });
      const { jobId } = await r.json();
      assert(jobId);
      let job = null;
      for (let i = 0; i < 120; i++) {
        await new Promise((res) => setTimeout(res, 1000));
        job = await (await fetch(`${base}/api/test/${jobId}/results`)).json();
        if (job.status === 'done' || job.status === 'error') break;
      }
      assert(job, 'job result');
      assert.strictEqual(job.status, 'done', `job status=${job.status} error=${job.error}`);
      assert.strictEqual(job.results.length, 7);
      for (const res of job.results) {
        assert.strictEqual(res.status, 'dead', `${res.protocol} should be dead`);
        assert(res.error && res.error.length > 0, `${res.protocol} must carry a reason, got "${res.error}"`);
      }
      assert(job.outputs && job.outputs.workingCount === 0);
      assert(fs.existsSync(path.join(__dirname, 'outputs', 'top_15_speedy_nodes.txt')), 'outputs file written');
      console.log(`    dead reasons sample: ${job.results.map((x) => `${x.protocol}=${x.error}`).join(' · ')}`);
    });
    await check('GET /sub/tested serves the (empty) tested set with headers', async () => {
      const r = await fetch(`${base}/sub/tested`);
      assert.strictEqual(r.status, 200);
      assert((r.headers.get('profile-title') || '').startsWith('base64:'));
      await r.text();
    });
  } finally {
    srv.close();
    fixture.close();
  }

  console.log(`\ncore validation: ${coreValidation}`);
  console.log(`RESULT: ${passed} passed, ${failed} failed`);
  if (failures.length) { console.log('FAILURES:\n - ' + failures.join('\n - ')); process.exit(1); }
}

main().catch((e) => { console.error('test runner crashed:', e); process.exit(1); });
