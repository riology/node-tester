function generateUuid() {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

const KNOWN_SCHEMES = ['vless://', 'vmess://', 'ss://', 'trojan://', 'hy2://', 'hysteria2://', 'tuic://'];

/**
 * Safely decode Base64 (supports standard, URL-safe, and unpadded strings)
 */
function safeBase64Decode(str) {
  if (!str || typeof str !== 'string') return '';
  let cleaned = str.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padMod = cleaned.length % 4;
  if (padMod === 2) cleaned += '==';
  else if (padMod === 3) cleaned += '=';
  else if (padMod === 1) return '';
  try {
    if (typeof Buffer !== 'undefined') {
      return Buffer.from(cleaned, 'base64').toString('utf8');
    }
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder('utf-8').decode(bytes);
  } catch {
    return '';
  }
}

/**
 * Safely encode string to standard Base64 (with padding)
 */
function safeBase64Encode(str) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(String(str), 'utf8').toString('base64');
  }
  const bytes = new TextEncoder().encode(String(str));
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Check if a string looks like a Base64 blob that decodes to VPN URIs
 */
function tryDecodeBase64Block(text) {
  const trimmed = text.trim();
  if (!trimmed || KNOWN_SCHEMES.some((s) => trimmed.toLowerCase().startsWith(s))) {
    return null;
  }
  const compact = trimmed.replace(/\s+/g, '');
  if (compact.length < 16 || !/^[A-Za-z0-9+/=_-]+$/.test(compact)) {
    return null;
  }
  const decoded = safeBase64Decode(compact);
  if (!decoded) return null;
  const lower = decoded.toLowerCase();
  if (KNOWN_SCHEMES.some((s) => lower.includes(s))) {
    return decoded;
  }
  return null;
}

/**
 * Parse raw input text (can be raw links, Base64 subscription, JSON outbounds, or mixed)
 * and return an array of individual URI strings or structured objects.
 */
function extractRawEntries(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') return { entries: [], inputType: 'empty' };
  const trimmed = rawInput.trim();
  if (!trimmed) return { entries: [], inputType: 'empty' };

  // 1. Check if entire block is Base64
  const fullDecoded = tryDecodeBase64Block(trimmed);
  if (fullDecoded) {
    const subResult = extractRawEntries(fullDecoded);
    return { entries: subResult.entries, inputType: 'base64' };
  }

  // 2. Check if entire block is JSON (Xray or Sing-box config / outbound)
  if ((trimmed.startsWith('{') && trimmed.endsWith('}')) || (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
    try {
      const parsedJson = JSON.parse(trimmed);
      const jsonNodes = extractNodesFromJson(parsedJson);
      if (jsonNodes.length > 0) {
        return { entries: jsonNodes, inputType: 'json' };
      }
    } catch {
      // Not valid JSON, continue line-by-line parsing
    }
  }

  // 3. Line-by-line / token-by-token extraction (handles mixed raw links + base64 chunks)
  const rawLines = trimmed.split(/[\r\n]+/);
  const entries = [];
  let hadBase64Line = false;
  let hadRawUri = false;

  for (const rawLine of rawLines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;

    // Check if line is a Base64 chunk
    const decodedChunk = tryDecodeBase64Block(line);
    if (decodedChunk) {
      hadBase64Line = true;
      const chunkLines = decodedChunk.split(/[\r\n]+/).map((l) => l.trim()).filter(Boolean);
      for (const cl of chunkLines) {
        entries.push({ type: 'uri', value: cl, fromBase64: true });
      }
      continue;
    }

    // Extract one or more URIs if pasted on the same line
    const schemeRegex = /(?:vless|vmess|ss|trojan|hy2|hysteria2|tuic):\/\/[^\s]+/gi;
    const matches = line.match(schemeRegex);
    if (matches && matches.length > 0) {
      hadRawUri = true;
      for (const m of matches) {
        entries.push({ type: 'uri', value: m.trim(), fromBase64: false });
      }
    }
  }

  let inputType = 'raw';
  if (hadBase64Line && hadRawUri) inputType = 'mixed';
  else if (hadBase64Line) inputType = 'base64';

  return { entries, inputType };
}

/**
 * Extract nodes from Xray-core or sing-box JSON objects
 */
function extractNodesFromJson(json) {
  const list = Array.isArray(json)
    ? json
    : Array.isArray(json.outbounds)
    ? json.outbounds
    : [json];

  const results = [];
  for (const item of list) {
    if (!item || typeof item !== 'object') continue;
    // Sing-box format
    if (item.type && item.server && item.server_port) {
      results.push({ type: 'singbox_json', value: item });
    }
    // Xray format
    else if (item.protocol && item.settings) {
      results.push({ type: 'xray_json', value: item });
    }
  }
  return results;
}

/**
 * Parse query string manually to preserve raw values and detect empty/duplicate params
 */
function parseQueryParams(queryString) {
  const params = {};
  const fixes = [];
  if (!queryString) return { params, fixes };

  const pairs = queryString.split('&');
  for (const pair of pairs) {
    if (!pair) continue;
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) {
      params[decodeURIComponent(pair)] = '';
      continue;
    }
    const rawKey = pair.slice(0, eqIdx);
    const rawVal = pair.slice(eqIdx + 1);
    let key = rawKey;
    try {
      key = decodeURIComponent(rawKey);
    } catch {
      key = rawKey;
    }

    if (rawVal === '') {
      fixes.push(`Removed empty parameter "${key}="`);
      continue;
    }

    let val = rawVal;
    try {
      val = decodeURIComponent(rawVal);
    } catch {
      val = rawVal;
    }

    if ((key === 'path' || key === 'spx') && rawVal.includes('/')) {
      fixes.push(`Normalized unencoded slashes in "${key}"`);
    }

    params[key] = val;
  }

  if ('insecure' in params && 'allowInsecure' in params) {
    fixes.push('Consolidated duplicate insecure/allowInsecure flags');
  }

  return { params, fixes };
}

/**
 * Parse host and port from "host:port" or "[ipv6]:port"
 */
function parseHostPort(hostPortStr) {
  if (!hostPortStr) return { host: '', port: 443 };
  if (hostPortStr.startsWith('[')) {
    const closeBracket = hostPortStr.indexOf(']');
    if (closeBracket !== -1) {
      const host = hostPortStr.slice(1, closeBracket);
      const portStr = hostPortStr.slice(closeBracket + 2);
      return { host, port: parseInt(portStr, 10) || 443 };
    }
  }
  const lastColon = hostPortStr.lastIndexOf(':');
  if (lastColon === -1) {
    return { host: hostPortStr, port: 443 };
  }
  return {
    host: hostPortStr.slice(0, lastColon),
    port: parseInt(hostPortStr.slice(lastColon + 1), 10) || 443,
  };
}

/**
 * Parse a single URI or JSON entry into a normalized Node object
 */
function parseNodeEntry(entry, index = 0) {
  if (entry.type === 'singbox_json') {
    return parseSingBoxOutbound(entry.value, index);
  }
  if (entry.type === 'xray_json') {
    return parseXrayOutbound(entry.value, index);
  }

  const uri = entry.value.trim();
  const lower = uri.toLowerCase();

  if (lower.startsWith('vless://')) return parseVlessUri(uri, index, entry.fromBase64);
  if (lower.startsWith('ss://')) return parseShadowsocksUri(uri, index, entry.fromBase64);
  if (lower.startsWith('vmess://')) return parseVmessUri(uri, index, entry.fromBase64);
  if (lower.startsWith('trojan://')) return parseTrojanUri(uri, index, entry.fromBase64);
  if (lower.startsWith('hy2://') || lower.startsWith('hysteria2://')) return parseHysteria2Uri(uri, index, entry.fromBase64);
  if (lower.startsWith('tuic://')) return parseTuicUri(uri, index, entry.fromBase64);

  return null;
}

/**
 * Parse VLESS URI: vless://uuid@host:port?params#remark
 */
function parseVlessUri(uri, index, fromBase64 = false) {
  const withoutScheme = uri.slice('vless://'.length);
  const hashIdx = withoutScheme.indexOf('#');
  const mainPart = hashIdx === -1 ? withoutScheme : withoutScheme.slice(0, hashIdx);
  const rawRemark = hashIdx === -1 ? '' : withoutScheme.slice(hashIdx + 1);

  let remark = `vless-${index + 1}`;
  if (rawRemark) {
    try {
      remark = decodeURIComponent(rawRemark);
    } catch {
      remark = rawRemark;
    }
  }

  const qIdx = mainPart.indexOf('?');
  const authority = qIdx === -1 ? mainPart : mainPart.slice(0, qIdx);
  const queryStr = qIdx === -1 ? '' : mainPart.slice(qIdx + 1);

  const atIdx = authority.lastIndexOf('@');
  if (atIdx === -1) return null;

  const uuid = decodeURIComponent(authority.slice(0, atIdx));
  const { host, port } = parseHostPort(authority.slice(atIdx + 1));
  const { params, fixes } = parseQueryParams(queryStr);

  const transport = (params.type || 'tcp').toLowerCase();
  const security = (params.security || 'none').toLowerCase();
  const insecure =
    params.allowInsecure === '1' ||
    params.allowInsecure === 'true' ||
    params.insecure === '1' ||
    params.insecure === 'true';

  if (security === 'reality' && !params.sid) {
    fixes.push('Reality shortId (sid) was omitted; defaulted to empty ""');
  }

  const node = {
    id: generateUuid(),
    index,
    protocol: 'vless',
    remark,
    originalRemark: remark,
    host,
    port,
    uuid,
    encryption: params.encryption || 'none',
    flow: params.flow || '',
    transport,
    security,
    sni: params.sni || params.peer || '',
    fp: params.fp || 'chrome',
    alpn: params.alpn ? params.alpn.split(',').map((s) => s.trim()).filter(Boolean) : [],
    pbk: params.pbk || '',
    sid: params.sid || '',
    spx: params.spx || '',
    headerType: params.headerType || 'none',
    wsHost: params.host || '',
    path: params.path || '',
    mode: params.mode || (transport === 'xhttp' ? 'auto' : ''),
    serviceName: params.serviceName || '',
    authority: params.authority || '',
    insecure,
    fromBase64,
    fixes,
    originalUri: uri,
  };

  return enrichNodeMetadata(node);
}

/**
 * Parse Shadowsocks URI:
 * - SIP002: ss://base64(method:password)@host:port#remark
 * - Legacy: ss://base64(method:password@host:port)#remark
 * - Plain:  ss://method:password@host:port#remark
 */
function parseShadowsocksUri(uri, index, fromBase64 = false) {
  const withoutScheme = uri.slice('ss://'.length);
  const hashIdx = withoutScheme.indexOf('#');
  const mainPart = hashIdx === -1 ? withoutScheme : withoutScheme.slice(0, hashIdx);
  const rawRemark = hashIdx === -1 ? '' : withoutScheme.slice(hashIdx + 1);

  let remark = `ss-${index + 1}`;
  if (rawRemark) {
    try {
      remark = decodeURIComponent(rawRemark);
    } catch {
      remark = rawRemark;
    }
  }

  const qIdx = mainPart.indexOf('?');
  const authorityPart = qIdx === -1 ? mainPart : mainPart.slice(0, qIdx);
  const queryStr = qIdx === -1 ? '' : mainPart.slice(qIdx + 1);
  const { params, fixes } = parseQueryParams(queryStr);

  let method = '';
  let password = '';
  let host = '';
  let port = 443;

  const atIdx = authorityPart.lastIndexOf('@');
  if (atIdx !== -1) {
    const userInfo = authorityPart.slice(0, atIdx);
    const hostPort = parseHostPort(authorityPart.slice(atIdx + 1));
    host = hostPort.host;
    port = hostPort.port;

    if (userInfo.includes(':')) {
      const colonIdx = userInfo.indexOf(':');
      method = decodeURIComponent(userInfo.slice(0, colonIdx));
      password = decodeURIComponent(userInfo.slice(colonIdx + 1));
    } else {
      if (userInfo.length % 4 !== 0) {
        fixes.push('Fixed unpadded Base64 userinfo in ss:// URI');
      }
      const decodedUser = safeBase64Decode(userInfo);
      const colonIdx = decodedUser.indexOf(':');
      if (colonIdx !== -1) {
        method = decodedUser.slice(0, colonIdx);
        password = decodedUser.slice(colonIdx + 1);
      }
    }
  } else {
    // Legacy format where entire method:pass@host:port is base64 encoded
    if (authorityPart.length % 4 !== 0) {
      fixes.push('Fixed unpadded Base64 authority in ss:// URI');
    }
    const decodedAll = safeBase64Decode(authorityPart);
    const decodedAt = decodedAll.lastIndexOf('@');
    if (decodedAt !== -1) {
      const userInfo = decodedAll.slice(0, decodedAt);
      const hostPort = parseHostPort(decodedAll.slice(decodedAt + 1));
      host = hostPort.host;
      port = hostPort.port;
      const colonIdx = userInfo.indexOf(':');
      if (colonIdx !== -1) {
        method = userInfo.slice(0, colonIdx);
        password = userInfo.slice(colonIdx + 1);
      }
    }
  }

  if (!host || !method) return null;

  const node = {
    id: generateUuid(),
    index,
    protocol: 'ss',
    remark,
    originalRemark: remark,
    host,
    port,
    method,
    password,
    plugin: params.plugin || '',
    transport: 'tcp',
    security: 'none',
    fromBase64,
    fixes,
    originalUri: uri,
  };

  return enrichNodeMetadata(node);
}

/**
 * Parse VMess URI: vmess://base64(json)
 */
function parseVmessUri(uri, index, fromBase64 = false) {
  const b64Part = uri.slice('vmess://'.length).trim();
  const fixes = [];
  if (b64Part.length % 4 !== 0) {
    fixes.push('Fixed unpadded Base64 payload in vmess:// URI');
  }
  const decoded = safeBase64Decode(b64Part);
  if (!decoded) return null;

  try {
    const j = JSON.parse(decoded);
    const transport = (j.net || 'tcp').toLowerCase();
    const security = (j.tls || 'none').toLowerCase();
    const remark = j.ps || `vmess-${index + 1}`;
    const node = {
      id: generateUuid(),
      index,
      protocol: 'vmess',
      remark,
      originalRemark: remark,
      host: j.add || '',
      port: parseInt(j.port, 10) || 443,
      uuid: j.id || '',
      aid: parseInt(j.aid || '0', 10) || 0,
      cipher: j.scy || 'auto',
      transport,
      headerType: j.type || 'none',
      wsHost: j.host || '',
      path: j.path || '',
      security: security === 'tls' ? 'tls' : 'none',
      sni: j.sni || j.host || '',
      fp: j.fp || 'chrome',
      alpn: j.alpn ? String(j.alpn).split(',').map((s) => s.trim()).filter(Boolean) : [],
      insecure: Boolean(j.allowInsecure),
      fromBase64,
      fixes,
      originalUri: uri,
    };
    return enrichNodeMetadata(node);
  } catch {
    return null;
  }
}

/**
 * Parse Trojan URI: trojan://password@host:port?params#remark
 */
function parseTrojanUri(uri, index, fromBase64 = false) {
  const withoutScheme = uri.slice('trojan://'.length);
  const hashIdx = withoutScheme.indexOf('#');
  const mainPart = hashIdx === -1 ? withoutScheme : withoutScheme.slice(0, hashIdx);
  const rawRemark = hashIdx === -1 ? '' : withoutScheme.slice(hashIdx + 1);

  let remark = `trojan-${index + 1}`;
  if (rawRemark) {
    try {
      remark = decodeURIComponent(rawRemark);
    } catch {
      remark = rawRemark;
    }
  }

  const qIdx = mainPart.indexOf('?');
  const authority = qIdx === -1 ? mainPart : mainPart.slice(0, qIdx);
  const queryStr = qIdx === -1 ? '' : mainPart.slice(qIdx + 1);

  const atIdx = authority.lastIndexOf('@');
  if (atIdx === -1) return null;

  const password = decodeURIComponent(authority.slice(0, atIdx));
  const { host, port } = parseHostPort(authority.slice(atIdx + 1));
  const { params, fixes } = parseQueryParams(queryStr);

  const transport = (params.type || 'tcp').toLowerCase();
  const security = (params.security || 'tls').toLowerCase();
  const insecure =
    params.allowInsecure === '1' ||
    params.allowInsecure === 'true' ||
    params.insecure === '1' ||
    params.insecure === 'true';

  const node = {
    id: generateUuid(),
    index,
    protocol: 'trojan',
    remark,
    originalRemark: remark,
    host,
    port,
    password,
    transport,
    security,
    sni: params.sni || params.peer || host,
    fp: params.fp || 'chrome',
    alpn: params.alpn ? params.alpn.split(',').map((s) => s.trim()).filter(Boolean) : [],
    pbk: params.pbk || '',
    sid: params.sid || '',
    wsHost: params.host || '',
    path: params.path || '',
    serviceName: params.serviceName || '',
    headerType: params.headerType || 'none',
    insecure,
    fromBase64,
    fixes,
    originalUri: uri,
  };

  return enrichNodeMetadata(node);
}

/**
 * Parse Hysteria2 URI: hy2://password@host:port?params#remark
 */
function parseHysteria2Uri(uri, index, fromBase64 = false) {
  // node-tester patch: upstream regex did not strip the short "hy2://" scheme,
  // which corrupted the parsed password. Accept both hy2:// and hysteria2://.
  const withoutScheme = uri.replace(/^(?:hysteria2|hy2):\/\//i, '');
  const hashIdx = withoutScheme.indexOf('#');
  const mainPart = hashIdx === -1 ? withoutScheme : withoutScheme.slice(0, hashIdx);
  const rawRemark = hashIdx === -1 ? '' : withoutScheme.slice(hashIdx + 1);

  let remark = `hy2-${index + 1}`;
  if (rawRemark) {
    try {
      remark = decodeURIComponent(rawRemark);
    } catch {
      remark = rawRemark;
    }
  }

  const qIdx = mainPart.indexOf('?');
  const authority = qIdx === -1 ? mainPart : mainPart.slice(0, qIdx);
  const queryStr = qIdx === -1 ? '' : mainPart.slice(qIdx + 1);

  const atIdx = authority.lastIndexOf('@');
  if (atIdx === -1) return null;

  const password = decodeURIComponent(authority.slice(0, atIdx));
  const { host, port } = parseHostPort(authority.slice(atIdx + 1));
  const { params, fixes } = parseQueryParams(queryStr);

  const node = {
    id: generateUuid(),
    index,
    protocol: 'hy2',
    remark,
    originalRemark: remark,
    host,
    port,
    password,
    transport: 'quic',
    security: 'tls',
    sni: params.sni || host,
    alpn: params.alpn ? params.alpn.split(',').map((s) => s.trim()).filter(Boolean) : ['h3'],
    obfs: params.obfs || '',
    obfsPassword: params['obfs-password'] || '',
    insecure: params.insecure === '1' || params.insecure === 'true',
    fromBase64,
    fixes,
    originalUri: uri,
  };

  return enrichNodeMetadata(node);
}

/**
 * Parse TUIC v5 URI: tuic://uuid:password@host:port?params#remark
 */
function parseTuicUri(uri, index, fromBase64 = false) {
  const withoutScheme = uri.slice('tuic://'.length);
  const hashIdx = withoutScheme.indexOf('#');
  const mainPart = hashIdx === -1 ? withoutScheme : withoutScheme.slice(0, hashIdx);
  const rawRemark = hashIdx === -1 ? '' : withoutScheme.slice(hashIdx + 1);

  let remark = `tuic-${index + 1}`;
  if (rawRemark) {
    try {
      remark = decodeURIComponent(rawRemark);
    } catch {
      remark = rawRemark;
    }
  }

  const qIdx = mainPart.indexOf('?');
  const authority = qIdx === -1 ? mainPart : mainPart.slice(0, qIdx);
  const queryStr = qIdx === -1 ? '' : mainPart.slice(qIdx + 1);

  const atIdx = authority.lastIndexOf('@');
  if (atIdx === -1) return null;

  const userInfo = authority.slice(0, atIdx);
  const colonIdx = userInfo.indexOf(':');
  const uuid = colonIdx === -1 ? decodeURIComponent(userInfo) : decodeURIComponent(userInfo.slice(0, colonIdx));
  const password = colonIdx === -1 ? '' : decodeURIComponent(userInfo.slice(colonIdx + 1));
  const { host, port } = parseHostPort(authority.slice(atIdx + 1));
  const { params, fixes } = parseQueryParams(queryStr);

  const node = {
    id: generateUuid(),
    index,
    protocol: 'tuic',
    remark,
    originalRemark: remark,
    host,
    port,
    uuid,
    password,
    transport: 'quic',
    security: 'tls',
    sni: params.sni || host,
    alpn: params.alpn ? params.alpn.split(',').map((s) => s.trim()).filter(Boolean) : ['h3'],
    congestionControl: params.congestion_control || 'bbr',
    udpRelayMode: params.udp_relay_mode || 'native',
    insecure: params.allow_insecure === '1' || params.insecure === '1',
    fromBase64,
    fixes,
    originalUri: uri,
  };

  return enrichNodeMetadata(node);
}

/**
 * Parse Sing-box JSON outbound into normalized Node
 */
function parseSingBoxOutbound(item, index) {
  const protoMap = { shadowsocks: 'ss', hysteria2: 'hy2' };
  const protocol = protoMap[item.type] || item.type;
  const tls = item.tls || {};
  const reality = tls.reality || {};
  const transportObj = item.transport || {};

  const node = {
    id: generateUuid(),
    index,
    protocol,
    remark: item.tag || `${protocol}-${index + 1}`,
    originalRemark: item.tag || `${protocol}-${index + 1}`,
    host: item.server,
    port: item.server_port || 443,
    uuid: item.uuid || '',
    password: item.password || '',
    method: item.method || 'aes-256-gcm',
    flow: item.flow || '',
    encryption: 'none',
    transport: transportObj.type || 'tcp',
    security: reality.enabled ? 'reality' : tls.enabled ? 'tls' : 'none',
    sni: tls.server_name || '',
    fp: (tls.utls && tls.utls.fingerprint) || 'chrome',
    alpn: Array.isArray(tls.alpn) ? tls.alpn : [],
    pbk: reality.public_key || '',
    sid: reality.short_id || '',
    path: transportObj.path || '',
    wsHost: (transportObj.headers && transportObj.headers.Host) || '',
    serviceName: transportObj.service_name || '',
    insecure: Boolean(tls.insecure),
    fromBase64: false,
    fixes: ['Imported from sing-box JSON outbound'],
    originalUri: '',
  };

  return enrichNodeMetadata(node);
}

/**
 * Parse Xray JSON outbound into normalized Node
 */
function parseXrayOutbound(item, index) {
  const protoMap = { shadowsocks: 'ss' };
  const protocol = protoMap[item.protocol] || item.protocol;
  const stream = item.streamSettings || {};
  const transport = stream.network || 'tcp';
  const security = stream.security || 'none';
  const reality = stream.realitySettings || {};
  const tls = stream.tlsSettings || {};
  const xhttp = stream.xhttpSettings || {};
  const grpc = stream.grpcSettings || {};
  const ws = stream.wsSettings || {};

  let host = '';
  let port = 443;
  let uuid = '';
  let password = '';
  let method = '';
  let flow = '';

  if (Array.isArray(item.settings?.vnext) && item.settings.vnext[0]) {
    const v = item.settings.vnext[0];
    host = v.address;
    port = v.port;
    if (Array.isArray(v.users) && v.users[0]) {
      uuid = v.users[0].id || '';
      flow = v.users[0].flow || '';
    }
  } else if (Array.isArray(item.settings?.servers) && item.settings.servers[0]) {
    const s = item.settings.servers[0];
    host = s.address;
    port = s.port;
    password = s.password || '';
    method = s.method || '';
  }

  const node = {
    id: generateUuid(),
    index,
    protocol,
    remark: item.tag || `${protocol}-${index + 1}`,
    originalRemark: item.tag || `${protocol}-${index + 1}`,
    host,
    port,
    uuid,
    password,
    method,
    flow,
    encryption: 'none',
    transport,
    security,
    sni: reality.serverName || tls.serverName || '',
    fp: reality.fingerprint || tls.fingerprint || 'chrome',
    alpn: Array.isArray(tls.alpn) ? tls.alpn : [],
    pbk: reality.publicKey || '',
    sid: reality.shortId || '',
    spx: reality.spiderX || '',
    path: xhttp.path || ws.path || '',
    mode: xhttp.mode || '',
    wsHost: xhttp.host || (ws.headers && ws.headers.Host) || '',
    serviceName: grpc.serviceName || '',
    insecure: Boolean(tls.allowInsecure),
    fromBase64: false,
    fixes: ['Imported from Xray-core JSON outbound'],
    originalUri: '',
  };

  return enrichNodeMetadata(node);
}

/**
 * Compute compatibility flags, fingerprint hash (for deduplication), and normalized URI
 */
function enrichNodeMetadata(node) {
  const unsupportedSingBoxTransports = ['xhttp', 'splithttp', 'kcp'];
  const isSingBoxCompatible = !unsupportedSingBoxTransports.includes(node.transport);
  const isXrayCompatible = !['hy2', 'tuic'].includes(node.protocol);

  const compatibilityNotes = [];
  if (!isSingBoxCompatible) {
    compatibilityNotes.push(
      `Transport "${node.transport}" is Xray-core specific (supported in v2rayNG / Hiddify Xray mode, not supported in pure sing-box)`
    );
  }
  if (!isXrayCompatible) {
    compatibilityNotes.push(`Protocol "${node.protocol.toUpperCase()}" is native to sing-box / Hiddify`);
  }

  node.compatibility = {
    xray: isXrayCompatible,
    singbox: isSingBoxCompatible,
    both: isXrayCompatible && isSingBoxCompatible,
    badge:
      isXrayCompatible && isSingBoxCompatible
        ? 'Both (Xray & Sing-box)'
        : isXrayCompatible
        ? 'Xray-core Only'
        : 'Sing-box Only',
    notes: compatibilityNotes,
  };

  // Deduplication signature based on endpoint + auth + transport + security
  const sigParts = [
    node.protocol,
    node.host,
    node.port,
    node.uuid || node.password || '',
    node.transport,
    node.security,
    node.pbk || '',
    node.path || '',
    node.serviceName || '',
  ];
  node.dedupKey = sigParts.join('|').toLowerCase();
  // Also compute credential-level signature (same UUID + PBK + SID on same port)
  node.credentialKey = [
    node.protocol,
    node.port,
    node.uuid || node.password || '',
    node.pbk || '',
    node.sid || '',
    node.path || '',
  ]
    .join('|')
    .toLowerCase();

  node.normalizedUri = toShareUri(node);
  return node;
}

/**
 * Serialize a normalized Node back to a clean, standard Share URI
 */
function toShareUri(node) {
  const remarkEncoded = encodeURIComponent(node.remark || `${node.protocol}-${node.index + 1}`);
  const hostFormatted = node.host.includes(':') && !node.host.startsWith('[') ? `[${node.host}]` : node.host;

  if (node.protocol === 'vless') {
    const q = new URLSearchParams();
    q.set('encryption', node.encryption || 'none');
    if (node.flow) q.set('flow', node.flow);
    q.set('security', node.security || 'none');
    q.set('type', node.transport || 'tcp');

    if (node.sni) q.set('sni', node.sni);
    if (node.fp) q.set('fp', node.fp);
    if (node.alpn && node.alpn.length > 0) q.set('alpn', node.alpn.join(','));

    if (node.security === 'reality') {
      if (node.pbk) q.set('pbk', node.pbk);
      if (node.sid) q.set('sid', node.sid);
      if (node.spx) q.set('spx', node.spx);
    } else if (node.security === 'tls') {
      if (node.insecure) q.set('allowInsecure', '1');
    }

    if (node.headerType && node.headerType !== 'none') {
      q.set('headerType', node.headerType);
    }
    if (node.wsHost) q.set('host', node.wsHost);
    if (node.path) q.set('path', node.path);
    if (node.mode && (node.transport === 'xhttp' || node.transport === 'splithttp')) {
      q.set('mode', node.mode);
    }
    if (node.serviceName && node.transport === 'grpc') {
      q.set('serviceName', node.serviceName);
    }

    return `vless://${encodeURIComponent(node.uuid)}@${hostFormatted}:${node.port}?${q.toString()}#${remarkEncoded}`;
  }

  if (node.protocol === 'ss') {
    const userPassB64 = safeBase64Encode(`${node.method}:${node.password}`);
    const query = node.plugin ? `?plugin=${encodeURIComponent(node.plugin)}` : '';
    return `ss://${userPassB64}@${hostFormatted}:${node.port}${query}#${remarkEncoded}`;
  }

  if (node.protocol === 'vmess') {
    const vmessObj = {
      v: '2',
      ps: node.remark,
      add: node.host,
      port: String(node.port),
      id: node.uuid,
      aid: String(node.aid || 0),
      scy: node.cipher || 'auto',
      net: node.transport || 'tcp',
      type: node.headerType || 'none',
      host: node.wsHost || '',
      path: node.path || '',
      tls: node.security === 'tls' ? 'tls' : '',
      sni: node.sni || '',
      alpn: (node.alpn || []).join(','),
      fp: node.fp || 'chrome',
    };
    return `vmess://${safeBase64Encode(JSON.stringify(vmessObj))}`;
  }

  if (node.protocol === 'trojan') {
    const q = new URLSearchParams();
    q.set('security', node.security || 'tls');
    q.set('type', node.transport || 'tcp');
    if (node.sni) q.set('sni', node.sni);
    if (node.fp) q.set('fp', node.fp);
    if (node.alpn && node.alpn.length > 0) q.set('alpn', node.alpn.join(','));
    if (node.security === 'reality') {
      if (node.pbk) q.set('pbk', node.pbk);
      if (node.sid) q.set('sid', node.sid);
    } else if (node.insecure) {
      q.set('allowInsecure', '1');
    }
    if (node.wsHost) q.set('host', node.wsHost);
    if (node.path) q.set('path', node.path);
    if (node.serviceName && node.transport === 'grpc') q.set('serviceName', node.serviceName);
    return `trojan://${encodeURIComponent(node.password)}@${hostFormatted}:${node.port}?${q.toString()}#${remarkEncoded}`;
  }

  if (node.protocol === 'hy2') {
    const q = new URLSearchParams();
    if (node.sni) q.set('sni', node.sni);
    if (node.insecure) q.set('insecure', '1');
    if (node.obfs) {
      q.set('obfs', node.obfs);
      if (node.obfsPassword) q.set('obfs-password', node.obfsPassword);
    }
    if (node.alpn && node.alpn.length > 0) q.set('alpn', node.alpn.join(','));
    return `hy2://${encodeURIComponent(node.password)}@${hostFormatted}:${node.port}?${q.toString()}#${remarkEncoded}`;
  }

  if (node.protocol === 'tuic') {
    const q = new URLSearchParams();
    if (node.sni) q.set('sni', node.sni);
    if (node.alpn && node.alpn.length > 0) q.set('alpn', node.alpn.join(','));
    if (node.congestionControl) q.set('congestion_control', node.congestionControl);
    if (node.udpRelayMode) q.set('udp_relay_mode', node.udpRelayMode);
    if (node.insecure) q.set('allow_insecure', '1');
    return `tuic://${encodeURIComponent(node.uuid)}:${encodeURIComponent(node.password)}@${hostFormatted}:${node.port}?${q.toString()}#${remarkEncoded}`;
  }

  return node.originalUri || '';
}

/**
 * Convert a single Node to a Sing-box Outbound object
 */
function nodeToSingBoxOutbound(node) {
  if (!node.compatibility.singbox) return null;

  const tag = node.remark;

  if (node.protocol === 'ss') {
    return {
      type: 'shadowsocks',
      tag,
      server: node.host,
      server_port: node.port,
      method: node.method,
      password: node.password,
    };
  }

  if (node.protocol === 'hy2') {
    const out = {
      type: 'hysteria2',
      tag,
      server: node.host,
      server_port: node.port,
      password: node.password,
      tls: {
        enabled: true,
        server_name: node.sni || node.host,
        insecure: Boolean(node.insecure),
        alpn: node.alpn && node.alpn.length > 0 ? node.alpn : ['h3'],
      },
    };
    if (node.obfs) {
      out.obfs = { type: node.obfs, password: node.obfsPassword || '' };
    }
    return out;
  }

  if (node.protocol === 'tuic') {
    return {
      type: 'tuic',
      tag,
      server: node.host,
      server_port: node.port,
      uuid: node.uuid,
      password: node.password,
      congestion_control: node.congestionControl || 'bbr',
      udp_relay_mode: node.udpRelayMode || 'native',
      tls: {
        enabled: true,
        server_name: node.sni || node.host,
        insecure: Boolean(node.insecure),
        alpn: node.alpn && node.alpn.length > 0 ? node.alpn : ['h3'],
      },
    };
  }

  // VLESS, VMess, Trojan
  const out = {
    type: node.protocol,
    tag,
    server: node.host,
    server_port: node.port,
  };

  if (node.protocol === 'vless') {
    out.uuid = node.uuid;
    if (node.flow && node.transport === 'tcp') {
      out.flow = node.flow;
    }
    out.packet_encoding = 'xudp';
  } else if (node.protocol === 'vmess') {
    out.uuid = node.uuid;
    out.security = node.cipher || 'auto';
    out.alter_id = node.aid || 0;
  } else if (node.protocol === 'trojan') {
    out.password = node.password;
  }

  // TLS / Reality
  if (node.security === 'tls' || node.security === 'reality') {
    const tlsObj = {
      enabled: true,
      server_name: node.sni || node.host,
      insecure: Boolean(node.insecure),
    };
    if (node.alpn && node.alpn.length > 0) {
      tlsObj.alpn = node.alpn;
    }
    if (node.fp) {
      tlsObj.utls = {
        enabled: true,
        fingerprint: node.fp,
      };
    }
    if (node.security === 'reality') {
      tlsObj.reality = {
        enabled: true,
        public_key: node.pbk,
        short_id: node.sid || '',
      };
    }
    out.tls = tlsObj;
  }

  // Transport
  if (node.transport === 'ws') {
    out.transport = {
      type: 'ws',
      path: node.path || '/',
      ...(node.wsHost ? { headers: { Host: node.wsHost } } : {}),
    };
  } else if (node.transport === 'grpc') {
    out.transport = {
      type: 'grpc',
      service_name: node.serviceName || '',
    };
  } else if (node.transport === 'httpupgrade') {
    out.transport = {
      type: 'httpupgrade',
      path: node.path || '/',
      ...(node.wsHost ? { host: node.wsHost } : {}),
    };
  }

  return out;
}

/**
 * Generate full Sing-box / Hiddify JSON profile
 */
function toSingBoxProfile(nodes) {
  const compatibleNodes = nodes.filter((n) => n.compatibility.singbox);
  const usedTags = new Set();
  const nodeOutbounds = [];

  for (const node of compatibleNodes) {
    const out = nodeToSingBoxOutbound(node);
    if (!out) continue;
    let uniqueTag = out.tag;
    let counter = 2;
    while (usedTags.has(uniqueTag)) {
      uniqueTag = `${out.tag}-${counter++}`;
    }
    usedTags.add(uniqueTag);
    out.tag = uniqueTag;
    nodeOutbounds.push(out);
  }

  const tags = nodeOutbounds.map((o) => o.tag);

  return {
    log: { level: 'warn', timestamp: true },
    dns: {
      servers: [
        { tag: 'dns-remote', address: 'https://1.1.1.1/dns-query', detour: 'select' },
        { tag: 'dns-direct', address: 'local', detour: 'direct' },
      ],
      rules: [{ outbound: 'any', server: 'dns-direct' }],
    },
    inbounds: [
      {
        type: 'mixed',
        tag: 'mixed-in',
        listen: '127.0.0.1',
        listen_port: 2080,
        sniff: true,
      },
    ],
    outbounds: [
      {
        type: 'selector',
        tag: 'select',
        outbounds: ['auto', ...tags, 'direct'],
        default: 'auto',
      },
      {
        type: 'urltest',
        tag: 'auto',
        outbounds: tags.length > 0 ? tags : ['direct'],
        url: 'https://www.gstatic.com/generate_204',
        interval: '3m',
        tolerance: 50,
      },
      ...nodeOutbounds,
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
    ],
    route: {
      auto_detect_interface: true,
      final: 'select',
    },
  };
}

/**
 * Convert a single Node to an Xray-core Outbound object
 */
function nodeToXrayOutbound(node) {
  if (!node.compatibility.xray) return null;

  const tag = node.remark;

  if (node.protocol === 'ss') {
    return {
      tag,
      protocol: 'shadowsocks',
      settings: {
        servers: [
          {
            address: node.host,
            port: node.port,
            method: node.method,
            password: node.password,
          },
        ],
      },
      streamSettings: {
        network: 'tcp',
        security: 'none',
      },
    };
  }

  const streamSettings = {
    network: node.transport || 'tcp',
    security: node.security || 'none',
  };

  if (node.security === 'reality') {
    streamSettings.realitySettings = {
      serverName: node.sni || '',
      fingerprint: node.fp || 'chrome',
      show: false,
      publicKey: node.pbk || '',
      shortId: node.sid || '',
      spiderX: node.spx || '',
    };
  } else if (node.security === 'tls') {
    streamSettings.tlsSettings = {
      serverName: node.sni || node.host,
      allowInsecure: Boolean(node.insecure),
      fingerprint: node.fp || 'chrome',
      ...(node.alpn && node.alpn.length > 0 ? { alpn: node.alpn } : {}),
    };
  }

  if (node.transport === 'xhttp' || node.transport === 'splithttp') {
    streamSettings.network = 'xhttp';
    streamSettings.xhttpSettings = {
      path: node.path || '/',
      mode: node.mode || 'auto',
      ...(node.wsHost ? { host: node.wsHost } : {}),
    };
  } else if (node.transport === 'grpc') {
    streamSettings.grpcSettings = {
      serviceName: node.serviceName || '',
      multiMode: false,
    };
  } else if (node.transport === 'ws') {
    streamSettings.wsSettings = {
      path: node.path || '/',
      ...(node.wsHost ? { headers: { Host: node.wsHost } } : {}),
    };
  } else if (node.transport === 'httpupgrade') {
    streamSettings.httpupgradeSettings = {
      path: node.path || '/',
      ...(node.wsHost ? { host: node.wsHost } : {}),
    };
  }

  if (node.protocol === 'vless') {
    return {
      tag,
      protocol: 'vless',
      settings: {
        vnext: [
          {
            address: node.host,
            port: node.port,
            users: [
              {
                id: node.uuid,
                encryption: node.encryption || 'none',
                ...(node.flow ? { flow: node.flow } : {}),
              },
            ],
          },
        ],
      },
      streamSettings,
    };
  }

  if (node.protocol === 'vmess') {
    return {
      tag,
      protocol: 'vmess',
      settings: {
        vnext: [
          {
            address: node.host,
            port: node.port,
            users: [
              {
                id: node.uuid,
                alterId: node.aid || 0,
                security: node.cipher || 'auto',
              },
            ],
          },
        ],
      },
      streamSettings,
    };
  }

  if (node.protocol === 'trojan') {
    return {
      tag,
      protocol: 'trojan',
      settings: {
        servers: [
          {
            address: node.host,
            port: node.port,
            password: node.password,
          },
        ],
      },
      streamSettings,
    };
  }

  return null;
}

/**
 * Generate full Xray-core JSON config
 */
function toXrayConfig(nodes) {
  const compatibleNodes = nodes.filter((n) => n.compatibility.xray);
  const outbounds = compatibleNodes.map((n) => nodeToXrayOutbound(n)).filter(Boolean);

  return {
    log: { loglevel: 'warning' },
    inbounds: [
      {
        tag: 'socks-in',
        port: 10808,
        listen: '127.0.0.1',
        protocol: 'socks',
        settings: { auth: 'noauth', udp: true },
        sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
      },
      {
        tag: 'http-in',
        port: 10809,
        listen: '127.0.0.1',
        protocol: 'http',
      },
    ],
    outbounds: [
      ...outbounds,
      { tag: 'direct', protocol: 'freedom', settings: {} },
      { tag: 'block', protocol: 'blackhole', settings: {} },
    ],
  };
}

/**
 * Generate a Clash / Mihomo (Clash.Meta) YAML profile
 */
function toClashProfile(nodes) {
  const usedNames = new Set();
  const uniqueName = (rawName, index) => {
    const base = (rawName || `node-${index + 1}`).replace(/[\r\n]+/g, ' ').trim();
    let candidate = base;
    let suffix = 2;
    while (usedNames.has(candidate)) {
      candidate = `${base} (${suffix++})`;
    }
    usedNames.add(candidate);
    return candidate;
  };

  const y = (val) => JSON.stringify(String(val ?? ''));
  const proxies = [];
  const proxyNames = [];

  nodes.forEach((node, idx) => {
    if (!node.compatibility?.singbox && node.transport === 'xhttp') return;
    const name = uniqueName(node.remark, idx);
    let item = null;

    if (node.protocol === 'vless') {
      item = {
        name,
        type: 'vless',
        server: node.host,
        port: node.port,
        uuid: node.uuid,
        udp: true,
        tls: node.security === 'tls' || node.security === 'reality',
      };
      if (node.flow) item.flow = node.flow;
      if (node.sni) item.servername = node.sni;
      if (node.fp) item['client-fingerprint'] = node.fp;
      if (node.insecure) item['skip-cert-verify'] = true;
      if (node.alpn?.length) item.alpn = node.alpn;
      if (node.security === 'reality') {
        item['reality-opts'] = {
          'public-key': node.pbk || '',
          ...(node.sid ? { 'short-id': node.sid } : {}),
        };
      }
      if (node.transport === 'ws' || node.transport === 'httpupgrade') {
        item.network = 'ws';
        item['ws-opts'] = {
          path: node.path || '/',
          ...(node.wsHost ? { headers: { Host: node.wsHost } } : {}),
        };
      } else if (node.transport === 'grpc') {
        item.network = 'grpc';
        item['grpc-opts'] = { 'grpc-service-name': node.serviceName || '' };
      } else {
        item.network = 'tcp';
      }
    } else if (node.protocol === 'vmess') {
      item = {
        name,
        type: 'vmess',
        server: node.host,
        port: node.port,
        uuid: node.uuid,
        alterId: node.alterId || 0,
        cipher: node.method || 'auto',
        udp: true,
        tls: node.security === 'tls',
      };
      if (node.sni) item.servername = node.sni;
      if (node.insecure) item['skip-cert-verify'] = true;
      if (node.transport === 'ws') {
        item.network = 'ws';
        item['ws-opts'] = {
          path: node.path || '/',
          ...(node.wsHost ? { headers: { Host: node.wsHost } } : {}),
        };
      } else if (node.transport === 'grpc') {
        item.network = 'grpc';
        item['grpc-opts'] = { 'grpc-service-name': node.serviceName || '' };
      }
    } else if (node.protocol === 'ss') {
      item = {
        name,
        type: 'ss',
        server: node.host,
        port: node.port,
        cipher: node.method || 'aes-256-gcm',
        password: node.password || '',
        udp: true,
      };
    } else if (node.protocol === 'trojan') {
      item = {
        name,
        type: 'trojan',
        server: node.host,
        port: node.port,
        password: node.password || '',
        udp: true,
      };
      if (node.sni) item.sni = node.sni;
      if (node.fp) item['client-fingerprint'] = node.fp;
      if (node.insecure) item['skip-cert-verify'] = true;
      if (node.alpn?.length) item.alpn = node.alpn;
      if (node.transport === 'ws') {
        item.network = 'ws';
        item['ws-opts'] = {
          path: node.path || '/',
          ...(node.wsHost ? { headers: { Host: node.wsHost } } : {}),
        };
      } else if (node.transport === 'grpc') {
        item.network = 'grpc';
        item['grpc-opts'] = { 'grpc-service-name': node.serviceName || '' };
      }
    } else if (node.protocol === 'hy2') {
      item = {
        name,
        type: 'hysteria2',
        server: node.host,
        port: node.port,
        password: node.password || '',
      };
      if (node.sni) item.sni = node.sni;
      if (node.insecure) item['skip-cert-verify'] = true;
      if (node.alpn?.length) item.alpn = node.alpn;
    } else if (node.protocol === 'tuic') {
      item = {
        name,
        type: 'tuic',
        server: node.host,
        port: node.port,
        uuid: node.uuid || '',
        password: node.password || '',
        'congestion-controller': node.congestionControl || 'bbr',
      };
      if (node.sni) item.sni = node.sni;
      if (node.insecure) item['skip-cert-verify'] = true;
      if (node.alpn?.length) item.alpn = node.alpn;
    }

    if (item) {
      proxies.push(item);
      proxyNames.push(name);
    }
  });

  const lines = [
    'mixed-port: 7890',
    'allow-lan: false',
    'mode: rule',
    'log-level: info',
    '',
    'proxies:',
  ];

  if (proxies.length === 0) {
    lines.push('  []');
  } else {
    for (const p of proxies) {
      lines.push(`  - ${JSON.stringify(p)}`);
    }
  }

  const groupMembers = proxyNames.length > 0 ? proxyNames : ['DIRECT'];
  lines.push(
    '',
    'proxy-groups:',
    `  - name: "PROXY"`,
    `    type: select`,
    `    proxies:`,
    ...(proxyNames.length > 0 ? ['      - "AUTO"'] : []),
    ...groupMembers.map((n) => `      - ${y(n)}`),
    `  - name: "AUTO"`,
    `    type: url-test`,
    `    url: "https://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...groupMembers.map((n) => `      - ${y(n)}`),
    '',
    'rules:',
    '  - MATCH,PROXY'
  );

  return lines.join('\n');
}

/**
 * High-level parse & process pipeline
 */
function processRawInput(rawInput, options = {}) {
  const {
    targetCore = 'all', // 'all' | 'singbox' | 'xray'
    deduplicate = false,
    remarkPrefix = '',
    renumberRemarks = false,
  } = options;

  const { entries, inputType } = extractRawEntries(rawInput);
  const allParsed = [];
  const errors = [];

  entries.forEach((entry, idx) => {
    const parsed = parseNodeEntry(entry, idx);
    if (parsed) {
      allParsed.push(parsed);
    } else {
      errors.push({ index: idx + 1, raw: entry.value });
    }
  });

  // Deduplication tracking
  const seenExact = new Set();
  const seenCredential = new Map();
  let duplicateCount = 0;

  const processed = [];
  for (const node of allParsed) {
    const isExactDup = seenExact.has(node.dedupKey);
    const matchingCredHost = seenCredential.get(node.credentialKey);
    node.isExactDuplicate = isExactDup;
    node.sameCredentialsAs = matchingCredHost && matchingCredHost !== node.host ? matchingCredHost : null;

    if (isExactDup) {
      duplicateCount++;
      if (deduplicate) continue;
    }
    seenExact.add(node.dedupKey);
    if (!seenCredential.has(node.credentialKey)) {
      seenCredential.set(node.credentialKey, node.host);
    }

    // Filter by targetCore
    if (targetCore === 'singbox' && !node.compatibility.singbox) {
      continue;
    }
    if (targetCore === 'xray' && !node.compatibility.xray) {
      continue;
    }

    processed.push({ ...node });
  }

  // Apply remark renaming if requested
  processed.forEach((node, idx) => {
    let remark = node.originalRemark;
    if (remarkPrefix && renumberRemarks) {
      const protoLabel = node.protocol.toUpperCase();
      remark = `${remarkPrefix}-${protoLabel}-${String(idx + 1).padStart(2, '0')}`;
    } else if (remarkPrefix) {
      remark = `${remarkPrefix} ${remark}`;
    } else if (renumberRemarks) {
      remark = `${remark} #${idx + 1}`;
    }
    node.remark = remark;
    node.normalizedUri = toShareUri(node);
  });

  const cleanUriList = processed.map((n) => n.normalizedUri).join('\n');
  const base64Sub = cleanUriList ? safeBase64Encode(cleanUriList) : '';
  const singBoxConfig = toSingBoxProfile(processed);
  const xrayConfig = toXrayConfig(processed);
  const clashYaml = toClashProfile(processed);

  const stats = {
    inputType,
    totalExtracted: allParsed.length,
    activeCount: processed.length,
    singBoxCompatibleCount: allParsed.filter((n) => n.compatibility.singbox).length,
    xrayOnlyCount: allParsed.filter((n) => n.compatibility.xray && !n.compatibility.singbox).length,
    singBoxOnlyCount: allParsed.filter((n) => !n.compatibility.xray && n.compatibility.singbox).length,
    duplicateCount,
    fixesAppliedCount: allParsed.reduce((sum, n) => sum + n.fixes.length, 0),
    errorCount: errors.length,
  };

  return {
    stats,
    nodes: processed,
    allNodes: allParsed,
    errors,
    outputs: {
      rawUris: cleanUriList,
      base64: base64Sub,
      singBoxJson: JSON.stringify(singBoxConfig, null, 2),
      xrayJson: JSON.stringify(xrayConfig, null, 2),
      clashYaml,
    },
  };
}

const exported = {
  safeBase64Decode,
  safeBase64Encode,
  extractRawEntries,
  parseNodeEntry,
  toShareUri,
  toSingBoxProfile,
  toXrayConfig,
  toClashProfile,
  processRawInput,
};

if (typeof module !== 'undefined' && module.exports) {
  module.exports = exported;
} else if (typeof globalThis !== 'undefined') {
  globalThis.VpnCore = exported;
}
