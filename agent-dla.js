#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { URL } = require('url');
const { program } = require('commander');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const { spawn } = require('child_process');

function collect(v, arr) { arr.push(v); return arr; }

program
  .name('agent-dla')
  .description('Agent Download Accelerator: parallel Range chunks, mirrors, proxy rotation, resume')
  .argument('[url]', 'file URL to download (or use --list)')
  .option('-o, --output <file>', 'output file path')
  .option('--dir <folder>', 'download into this folder (created if needed)')
  .option('--list <file>', 'batch mode: one URL per line (# comments allowed)')
  .option('--config <file>', 'config file (default: ./agent-dla.json if present)')
  .option('-n, --connections <n>', 'parallel connections (chunks), default 8, max 128', '8')
  .option('-p, --proxies <file>', 'proxy list file (default: ./proxies.txt if present)')
  .option('--mirror <url>', 'mirror URL serving the identical file (repeatable)', collect, [])
  .option('--timeout <ms>', 'per-request timeout ms', '15000')
  .option('--retries <n>', 'retries per chunk', '3')
  .option('--max-retries <n>', 'requeue rounds per chunk before aborting (parts are kept, rerun resumes)', '100')
  .option('--sha256 <hex>', 'verify file sha256 after download (bad output is deleted)')
  .option('--expect-size <size>', 'fail if final size differs (e.g. 10MB, 1.5GB, 1048576)')
  .option('--max-size <size>', 'refuse before / abort above this size')
  .option('--expect-type <mime>', 'fail if server content-type differs')
  .option('-k, --insecure', 'allow self-signed certs')
  .option('--no-auto-refresh', 'never auto-refresh the proxy list (default: refresh once when empty or all dead)')
  .option('--json', 'newline-delimited JSON events on stdout (human logs go to stderr)')
  .option('--redact', 'redact URL queries/credentials in human logs too (JSON events are always redacted)')
  .exitOverride();
program.configureOutput({
  writeOut: (str) => (process.argv.includes('--json') ? process.stderr : process.stdout).write(str),
  writeErr: (str) => process.stderr.write(str),
});
try {
  program.parse(process.argv);
} catch (e) {
  if (e.code === 'commander.helpDisplayed' || e.code === 'commander.version') process.exit(0);
  if (e.code && String(e.code).startsWith('commander.')) process.exit(2);
  throw e;
}

const opts = program.opts();
let HARVEST_TIMEOUT_MS = 0;
let HARVEST_SCRIPT = '';
function loadConfig() {
  const p = opts.config || (fs.existsSync(path.resolve('agent-dla.json')) ? path.resolve('agent-dla.json') : null);
  if (!p) return;
  let cfg;
  try { cfg = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { console.error(`bad config ${p}: ${e.message}`); process.exit(2); }
  const cli = (name) => program.getOptionValueSource(name) === 'cli';
  if (!cli('connections') && cfg.connections) opts.connections = String(cfg.connections);
  if (!cli('timeout') && cfg.timeout) opts.timeout = String(cfg.timeout);
  if (!cli('retries') && cfg.retries) opts.retries = String(cfg.retries);
  if (!cli('maxRetries') && cfg.maxRetries) opts.maxRetries = String(cfg.maxRetries);
  if (!cli('proxies') && cfg.proxies) opts.proxies = cfg.proxies;
  if (!cli('mirror') && Array.isArray(cfg.mirrors)) opts.mirror = cfg.mirrors;
  if (!cli('dir') && cfg.outputDir) opts.dir = cfg.outputDir;
  if (!cli('json') && cfg.json) opts.json = true;
  if (!cli('insecure') && cfg.insecure) opts.insecure = true;
  if (program.getOptionValueSource('autoRefresh') !== 'cli' && (cfg.autoRefresh === false || cfg.noAutoRefresh === true)) opts.autoRefresh = false;
  if (cfg.harvestTimeout) HARVEST_TIMEOUT_MS = parseInt(cfg.harvestTimeout, 10) || 0;
  if (cfg.harvestScript) HARVEST_SCRIPT = String(cfg.harvestScript);
  if (program.getOptionValueSource('redact') !== 'cli' && cfg.redact) opts.redact = true;
}
loadConfig();
function loadList(file) {
  if (!file) return [];
  const abs = path.resolve(file);
  if (!fs.existsSync(abs)) { console.error(`list file not found: ${abs}`); process.exit(2); }
  return fs.readFileSync(abs, 'utf8').split(/\r?\n/).map((l) => l.trim().replace(/\s+#.*$/, '')).filter((l) => l && !l.startsWith('#'));
}

const MAX_REDIRECTS = 10;
const MAX_PROXIES = 2048;
const CONNECTIONS = Math.min(Math.max(parseInt(opts.connections, 10) || 8, 1), 128);
const BENCH_CONC = Math.min(CONNECTIONS, 32);
const TIMEOUT = parseInt(opts.timeout, 10) || 15000;
const RETRIES = parseInt(opts.retries, 10) || 3;
const MAX_RETRIES = Math.min(Math.max(parseInt(opts.maxRetries, 10) || 100, 1), 1000);
function parseSize(s) {
  if (!s) return 0;
  const m = /^\s*([\d.]+)\s*([kmgt]?b?)?\s*$/i.exec(s);
  const mult = m && { '': 1, b: 1, k: 1024, kb: 1024, m: 1048576, mb: 1048576, g: 1073741824, gb: 1073741824, t: 1099511627776, tb: 1099511627776 }[m[2].toLowerCase()];
  if (!m || mult === undefined || !(parseFloat(m[1]) > 0)) { console.error(`bad size: ${s}`); process.exit(2); }
  return Math.round(parseFloat(m[1]) * mult);
}
const EXPECT_SHA = (opts.sha256 || '').trim().toLowerCase() || null;
if (EXPECT_SHA && !/^[0-9a-f]{64}$/.test(EXPECT_SHA)) { console.error('bad --sha256 (want 64 hex chars)'); process.exit(2); }
const EXPECT_SIZE = parseSize(opts.expectSize);
const MAX_SIZE = parseSize(opts.maxSize);
const EXPECT_TYPE = (opts.expectType || '').trim() || null;
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function backoffMs(fails) {
  return Math.min(1000 * 2 ** Math.min(fails, 5), 30000) + Math.random() * 1000;
}
async function backoff(fails) { await sleep(backoffMs(fails)); }
function parseRetryAfter(headers) {
  const v = headers['retry-after'];
  if (!v) return 0;
  if (/^\d+$/.test(v.trim())) return Math.min(parseInt(v, 10), 120);
  const t = Date.parse(v);
  if (!isNaN(t)) return Math.min(Math.max(Math.round((t - Date.now()) / 1000), 0), 120);
  return 0;
}
function httpError(status, headers, what) {
  const e = new Error(`HTTP ${status}${what ? ` for ${what}` : ''}`);
  e.status = status;
  e.retryAfter = parseRetryAfter(headers || {});
  return e;
}
// Show proxy as scheme://host:port only — credentials must never reach logs/events.
function redactProxy(p) {
  if (!p) return 'direct';
  try {
    const u = new URL(String(p).includes('://') ? String(p) : `http://${p}`);
    if (!u.hostname) return 'unparseable-proxy';
    return `${u.protocol}//${u.host}`;
  } catch { return 'unparseable-proxy'; }
}
// JSON events are persisted by agents: always strip credentials, query, fragment.
// Human logs keep the full URL unless --redact.
function displayUrl(u, forJson) {
  try {
    const x = new URL(String(u));
    x.username = '';
    x.password = '';
    if (forJson || opts.redact) { x.search = ''; x.hash = ''; }
    return x.toString();
  } catch { return (forJson || opts.redact) ? '[unparseable-url]' : String(u); }
}
function validTarget(t) {
  try {
    const u = new URL(String(t));
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}
// Shared redirect policy: capped chain, http(s) only, no https->http downgrade.
function redirectTarget(res, base, depth) {
  if (![301, 302, 303, 307, 308].includes(res.statusCode) || !res.headers.location) return null;
  if (depth >= MAX_REDIRECTS) { const e = new Error(`too many redirects (>${MAX_REDIRECTS})`); e.fatal = true; throw e; }
  let next;
  try { next = new URL(res.headers.location, base); }
  catch { const e = new Error(`bad redirect location: ${res.headers.location}`); e.fatal = true; throw e; }
  if (!/^https?:$/.test(next.protocol)) { const e = new Error(`refusing non-http redirect: ${next.protocol}`); e.fatal = true; throw e; }
  if (new URL(base).protocol === 'https:' && next.protocol === 'http:') { const e = new Error('refusing https->http downgrade'); e.fatal = true; throw e; }
  return next.toString();
}
// fatal: retrying is pointless (bad link, auth, deleted file). throttle: back
// off per Retry-After then continue. transient: rotate proxy and retry.
function classifyErr(e) {
  if (e && (e.fatal || e.code === 'SPLIT')) return e.code === 'SPLIT' ? 'split' : 'fatal';
  const st = e && e.status;
  if (st === 429 || st === 503) return 'throttle';
  if (st === 408) return 'transient';
  if (st >= 400 && st < 500) return 'fatal';
  return 'transient';
}
const JSON_MODE = !!opts.json;
// exit codes: 0 = complete, 1 = download failed, 2 = usage/config error
function emit(ev) { if (JSON_MODE) process.stdout.write(JSON.stringify(ev) + '\n'); }
function say(msg) { if (JSON_MODE) console.error(msg); else console.log(msg); }
function warn(msg) { emit({ event: 'warning', message: msg }); console.error((JSON_MODE ? '' : 'WARNING: ') + msg); }
let shutdownHandler = null;
process.on('SIGINT', () => { if (shutdownHandler) shutdownHandler('SIGINT'); else process.exit(130); });
process.on('SIGTERM', () => { if (shutdownHandler) shutdownHandler('SIGTERM'); else process.exit(130); });
const TLS_INSECURE = opts.insecure ? { rejectUnauthorized: false } : {};

function loadProxies(file) {
  if (!file) return [];
  const abs = path.resolve(file);
  if (!fs.existsSync(abs)) { console.error(`Proxy file not found: ${abs}`); process.exit(1); }
  return loadProxiesSoft(abs);
}

function loadProxiesSoft(file) {
  try {
    if (!file || !fs.existsSync(path.resolve(file))) return [];
    return fs.readFileSync(path.resolve(file), 'utf8').split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
  } catch { return []; }
}

let autoRefreshed = false; // at most one proxy harvest per process
function autoRefreshEnabled() {
  if (opts.autoRefresh === false) return false;
  if (process.env.AGENT_DLA_NO_AUTO_REFRESH === '1') return false;
  return true;
}

function runHarvest(outFile) {
  const script = process.env.AGENT_DLA_HARVEST_SCRIPT || HARVEST_SCRIPT || path.join(__dirname, 'get-proxies.js');
  const timeoutMs = parseInt(process.env.AGENT_DLA_HARVEST_TIMEOUT_MS || '', 10)
    || HARVEST_TIMEOUT_MS || 180000;
  // Never propagate a TLS bypass into the harvester: it fetches untrusted lists.
  const childEnv = { ...process.env };
  delete childEnv.NODE_TLS_REJECT_UNAUTHORIZED;
  return new Promise((resolve) => {
    const child = spawn('node', [script, outFile], { timeout: timeoutMs, env: childEnv });
    child.stdout.on('data', (d) => process.stderr.write(d));
    child.stderr.on('data', (d) => process.stderr.write(d));
    let done = false;
    const finish = (ok) => { if (!done) { done = true; resolve(ok); } };
    const kill = setTimeout(() => { try { child.kill(); } catch {} finish(false); }, timeoutMs + 5000);
    child.on('close', (code) => { clearTimeout(kill); finish(code === 0); });
    child.on('error', () => { clearTimeout(kill); finish(false); });
  });
}

// Only auto-fill files that look like proxy lists; never clobber foreign content.
function looksLikeProxyList(file) {
  const lines = loadProxiesSoft(file);
  if (!lines.length) return true;
  return lines.every((l) => /^(?:[a-zA-Z][a-zA-Z0-9+.-]*:\/\/)?(?:[^@/\s]+@)?[^/\s:]+:\d{1,5}$/.test(l));
}

async function refreshProxyList(reason) {
  autoRefreshed = true;
  const outFile = proxySource;
  if (!outFile) return;
  if (!looksLikeProxyList(outFile)) {
    emit({ event: 'proxies-refresh', phase: 'done', reason, file: outFile, candidates: 0, ok: false });
    say(`Proxy file ${outFile} does not look like a proxy list — not auto-refreshing, continuing direct.`);
    PROXIES = [];
    proxyIdx = 0;
    return;
  }
  try {
    if (fs.existsSync(outFile) && fs.statSync(outFile).size > 0) fs.copyFileSync(outFile, `${outFile}.bak`);
  } catch {}
  emit({ event: 'proxies-refresh', phase: 'start', reason, file: outFile });
  say(`Proxy list ${reason === 'empty' ? 'is empty' : 'has no working proxies'} — refreshing (${outFile})...`);
  const ok = await runHarvest(outFile);
  PROXIES = ok ? loadProxiesSoft(outFile) : []; // failed harvest: go direct, don't re-bench the known-dead list
  proxyIdx = 0;
  emit({ event: 'proxies-refresh', phase: 'done', reason, file: outFile, candidates: PROXIES.length, ok });
  say(ok ? `Refresh found ${PROXIES.length} candidate(s), re-checking...` : 'Refresh failed, continuing direct.');
}

const proxySource = opts.proxies
  || (fs.existsSync(path.resolve('proxies.txt')) ? path.resolve('proxies.txt') : null);
const PROXY_MIN_KBPS = 50;

let PROXIES = loadProxies(proxySource);
if (PROXIES.length > MAX_PROXIES) {
  warn(`Proxy list has ${PROXIES.length} entries, keeping first ${MAX_PROXIES}`);
  PROXIES = PROXIES.slice(0, MAX_PROXIES);
}
let proxyIdx = 0;
function nextProxy() {
  if (!PROXIES.length) return null;
  const p = PROXIES[proxyIdx % PROXIES.length];
  proxyIdx++;
  return p;
}

const directHttpAgent = new http.Agent({ keepAlive: true, maxSockets: 128 });
const directHttpsAgent = new https.Agent({ keepAlive: true, maxSockets: 128, ...TLS_INSECURE });

function filenameFromDisposition(headers) {
  const cd = headers['content-disposition'] || '';
  const m = /filename\*=UTF-8''([^;]+)/i.exec(cd)
    || /filename="([^"]+)"/i.exec(cd)
    || /filename=([^;]+)/i.exec(cd);
  if (!m) return null;
  let name = m[1].trim();
  try { name = decodeURIComponent(name); } catch {}
  name = name.replace(/[ -\\/;:*?"<>|]/g, '_').slice(0, 200);
  return name || null;
}

function mimeOf(headers) { return String(headers['content-type'] || '').split(';')[0].trim() || null; }

function isHtmlType(headers) {
  return mimeOf(headers) === 'text/html';
}

function fmtSize(b) {
  if (!b) return 'unknown';
  if (b >= 1048576) return (b / 1048576).toFixed(2) + ' MB';
  if (b >= 1024) return (b / 1024).toFixed(1) + ' KB';
  return b + ' bytes';
}

function agentFor(proxyUrl, targetIsHttps) {
  if (!proxyUrl) return targetIsHttps ? directHttpsAgent : directHttpAgent;
  const low = proxyUrl.toLowerCase();
  if (low.startsWith('socks')) return new SocksProxyAgent(proxyUrl, { timeout: TIMEOUT, ...TLS_INSECURE });
  return targetIsHttps ? new HttpsProxyAgent(proxyUrl, { timeout: TIMEOUT, ...TLS_INSECURE }) : new HttpProxyAgent(proxyUrl, { timeout: TIMEOUT, ...TLS_INSECURE });
}

function requestOnce(urlStr, headers, proxyUrl, depth = 0) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    const agent = agentFor(proxyUrl, isHttps);
    const req = lib.request(urlStr, {
      method: 'GET',
      headers: { 'User-Agent': 'agent-dla/1.0', ...headers },
      agent,
      timeout: TIMEOUT,
      ...TLS_INSECURE,
    }, (res) => {
      let next = null;
      try { next = redirectTarget(res, urlStr, depth); }
      catch (e) { res.resume(); reject(e); return; }
      if (next) {
        res.resume();
        resolve(requestOnce(next, headers, proxyUrl, depth + 1).then((r) => ({ ...r, finalUrl: r.finalUrl || next })));
        return;
      }
      // Probe only needs status/headers: cap the buffered body so a server
      // that ignores Range cannot blow up RAM with a multi-GB 200.
      const chunks = [];
      let buffered = 0;
      let settled = false;
      const finish = (body) => { if (!settled) { settled = true; resolve({ status: res.statusCode, headers: res.headers, body, finalUrl: urlStr }); } };
      res.on('data', (c) => {
        buffered += c.length;
        if (buffered <= 262144) chunks.push(c);
        else { try { req.destroy(); } catch {} try { res.destroy(); } catch {} finish(Buffer.concat(chunks)); }
      });
      res.on('end', () => finish(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

async function getFileInfo(url) {
  const attempts = Math.min(Math.max(1, PROXIES.length || 1), 32);
  const tried = new Set();
  let lastErr = new Error('probe failed');
  for (let i = 0; i < attempts; i++) {
    const proxy = nextProxy();
    if (tried.has(proxy)) break;
    tried.add(proxy);
    let r;
    try {
      r = await requestOnce(url, { Range: 'bytes=0-0' }, proxy);
    } catch (e) { lastErr = e; continue; }
    if (r.status === 206) {
      const cr = r.headers['content-range'] || '';
      const total = parseInt((cr.split('/')[1] || ''), 10);
      if (total > 0) return { size: total, range: true, finalUrl: r.finalUrl || url, filename: filenameFromDisposition(r.headers), html: isHtmlType(r.headers), mime: mimeOf(r.headers) };
    }
    if (r.status === 200) {
      const len = parseInt(r.headers['content-length'] || '0', 10);
      return { size: len || 0, range: false, finalUrl: r.finalUrl || url, filename: filenameFromDisposition(r.headers), html: isHtmlType(r.headers), mime: mimeOf(r.headers) };
    }
    lastErr = new Error(`probe via ${redactProxy(proxy)}: HTTP ${r.status}`);
  }
  // last resort: direct probe so dead proxies can't block the download
  try {
    const r = await requestOnce(url, { Range: 'bytes=0-0' }, null);
    if (r.status === 206) {
      const cr = r.headers['content-range'] || '';
      const total = parseInt((cr.split('/')[1] || ''), 10);
      if (total > 0) return { size: total, range: true, finalUrl: r.finalUrl || url, filename: filenameFromDisposition(r.headers), html: isHtmlType(r.headers), mime: mimeOf(r.headers) };
    }
    if (r.status === 200) {
      const len = parseInt(r.headers['content-length'] || '0', 10);
      return { size: len || 0, range: false, finalUrl: r.finalUrl || url, filename: filenameFromDisposition(r.headers), html: isHtmlType(r.headers), mime: mimeOf(r.headers) };
    }
    lastErr = new Error(`direct probe: HTTP ${r.status}`);
  } catch (e) { lastErr = e; }
  throw lastErr;
}

function downloadChunkToFile(url, start, end, partPath, proxyUrl, onProgress, token, depth = 0) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    const agent = agentFor(proxyUrl, isHttps);
    const req = lib.request(url, {
      method: 'GET',
      headers: { 'User-Agent': 'agent-dla/1.0', Range: `bytes=${start}-${end}` },
      agent,
      timeout: TIMEOUT,
      ...TLS_INSECURE,
    }, (res) => {
      let next = null;
      try { next = redirectTarget(res, url, depth); }
      catch (e) { res.resume(); reject(e); return; }
      if (next) {
        res.resume();
        downloadChunkToFile(next, start, end, partPath, proxyUrl, onProgress, token, depth + 1).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 206 && res.statusCode !== 200) {
        res.resume();
        reject(httpError(res.statusCode, res.headers, `${start}-${end}`));
        return;
      }
      const ws = fs.createWriteStream(partPath);
      let done = 0;
      res.on('data', (c) => { done += c.length; if (onProgress) onProgress(c.length); });
      res.pipe(ws);
      ws.on('finish', () => resolve(done));
      ws.on('error', reject);
      res.on('error', reject);
    });
    if (token) token.req = req;
    const timeoutErr = new Error('timeout');
    timeoutErr.code = 'TIMEOUT';
    req.on('timeout', () => req.destroy(timeoutErr));
    req.on('error', reject);
    req.end();
  });
}
async function downloadSingle(url, outPath, proxyUrl, totalSize, depth = 0) {
  const u = new URL(url);
  const isHttps = u.protocol === 'https:';
  const lib = isHttps ? https : http;
  let start = 0;
  if (fs.existsSync(outPath)) {
    const st = fs.statSync(outPath);
    if (totalSize && st.size < totalSize) start = st.size; // resume partial
    else if (totalSize && st.size === totalSize) { say('Already complete.'); return; }
    else if (!totalSize) { try { fs.unlinkSync(outPath); } catch {} } // unknown size: restart
  }
  if (start > 0) say(`Resuming single-stream at ${(start / 1048576).toFixed(1)} MB`);
  await new Promise((resolve, reject) => {
    const req = lib.request(url, {
      method: 'GET',
      headers: start > 0
        ? { 'User-Agent': 'agent-dla/1.0', Range: `bytes=${start}-` }
        : { 'User-Agent': 'agent-dla/1.0' },
      agent: agentFor(proxyUrl, isHttps),
      timeout: TIMEOUT,
      ...TLS_INSECURE,
    }, (res) => {
      let next = null;
      try { next = redirectTarget(res, url, depth); }
      catch (e) { res.resume(); reject(e); return; }
      if (next) {
        res.resume();
        downloadSingle(next, outPath, proxyUrl, totalSize, depth + 1).then(resolve, reject);
        return;
      }
      if (start > 0 && res.statusCode === 200) {
        start = 0; // server ignored Range: restart from scratch
        try { fs.unlinkSync(outPath); } catch {}
      }
      if (res.statusCode !== 200 && res.statusCode !== 206) { res.resume(); reject(httpError(res.statusCode, res.headers)); return; }
      const ws = fs.createWriteStream(outPath, { flags: start > 0 ? 'a' : 'w' });
      const total = totalSize || parseInt(res.headers['content-length'] || '0', 10) + start;
      let done = start; const t0 = Date.now();
      const draw = () => {
        const el = (Date.now() - t0) / 1000;
        process.stdout.write(`\r${fmtSize(done)}${total ? ' / ' + fmtSize(total) : ''} ${(el ? done / 1024 / el / 1024 : 0).toFixed(2)} MB/s   `);
      };
      const emitProg = () => {
        const el = (Date.now() - t0) / 1000;
        const spd = Math.round(done / Math.max(el, 0.01));
        emit({
          event: 'progress', bytes_done: done, total,
          speed_bps: spd, eta_s: spd > 0 && total ? Math.round((total - done) / spd) : null,
          chunks_done: total && done >= total ? 1 : 0, chunks_total: 1, active: 1, retries: 0, splits: 0,
        });
      };
      const timer = setInterval(() => { if (JSON_MODE) emitProg(); else draw(); }, JSON_MODE ? 1000 : 250);
      if (JSON_MODE) emitProg();
      res.on('data', (c) => {
        done += c.length;
        if (MAX_SIZE && done > MAX_SIZE) {
          const err = new Error(`exceeded --max-size ${fmtSize(MAX_SIZE)}`);
          err.fatal = true;
          req.destroy(err);
          try { res.destroy(); } catch {}
        }
      });
      res.pipe(ws);
      let settled = false;
      ws.on('finish', () => { if (settled) return; settled = true; clearInterval(timer); if (JSON_MODE) emitProg(); else { draw(); process.stdout.write('\n'); } resolve(); });
      const fail = (e) => { if (settled) return; settled = true; clearInterval(timer); try { ws.destroy(); } catch {} reject(e); };
      ws.on('error', fail);
      res.on('error', fail);
    });
    const timeoutErr = new Error('timeout');
    timeoutErr.code = 'TIMEOUT';
    req.on('timeout', () => req.destroy(timeoutErr));
    req.on('error', reject);
    req.end();
  });
}

// capped fetch (maxBytes) to measure path throughput without downloading the file
function benchFetch(urlStr, proxyUrl, maxBytes = 262144, depth = 0) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const finish = (bytes) => resolve({ bytes, ms: Date.now() - t0 });
    let got = 0, settled = false;
    const done = (bytes) => { if (!settled) { settled = true; finish(bytes); } };
    let u;
    try { u = new URL(urlStr); } catch { done(0); return; }
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    const req = lib.request(urlStr, {
      method: 'GET',
      headers: { 'User-Agent': 'agent-dla/1.0', Range: `bytes=0-${maxBytes - 1}` },
      agent: agentFor(proxyUrl, isHttps),
      timeout: TIMEOUT,
      ...TLS_INSECURE,
    }, (res) => {
      let next = null;
      try { next = redirectTarget(res, urlStr, depth); }
      catch { done(0); res.resume(); return; }
      if (next) {
        res.resume();
        benchFetch(next, proxyUrl, maxBytes, depth + 1).then((r) => done(r.bytes));
        return;
      }
      res.on('data', (c) => {
        got += c.length;
        if (got >= maxBytes) { done(got); req.destroy(); res.destroy(); }
      });
      res.on('end', () => done(got));
      res.on('error', () => done(got > 0 ? got : 0));
    });
    req.on('timeout', () => { req.destroy(); done(got); });
    req.on('error', () => done(got));
    req.end();
  });
}

async function benchAndFilter(url) {
  const intro = `Benchmarking ${PROXIES.length} proxies (256KB each)...`;
  if (JSON_MODE) process.stderr.write(intro); else process.stdout.write(intro);
  const d = await benchFetch(url, null);
  const dKbps = d.bytes / 1024 / Math.max(d.ms / 1000, 0.01);
  const results = [];
  const bqueue = [...PROXIES];
  await Promise.all(Array.from({ length: Math.min(BENCH_CONC, bqueue.length) }, async () => {
    while (bqueue.length) {
      const px = bqueue.shift();
      const r = await benchFetch(url, px).catch(() => ({ bytes: 0, ms: 1 }));
      results.push({ px, kbps: r.bytes / 1024 / Math.max(r.ms / 1000, 0.01) });
    }
  }));
  results.sort((a, b) => b.kbps - a.kbps);
  const bestKbps = results.length ? results[0].kbps : 0;
  const total = PROXIES.length;
  const keep = results.filter((r) => r.kbps >= PROXY_MIN_KBPS).slice(0, CONNECTIONS).map((r) => r.px);
  PROXIES = keep;
  proxyIdx = 0;
  return { keep, total, dropped: total - keep.length, dKbps, bestKbps, top: results.slice(0, 8) };
}

function reportBench(r) {
  say(` direct=${r.dKbps.toFixed(0)} KB/s best-proxy=${r.bestKbps.toFixed(0)} KB/s`);
  r.top.forEach((x) => say(`  ${redactProxy(x.px)} ${x.kbps.toFixed(0)} KB/s`));
  say(r.keep.length ? `Using ${r.keep.length}/${r.total} proxies (rest too slow/dead)` : 'All proxies too slow/dead, going direct-only');
  emit({ event: 'proxies', kept: r.keep.map((p) => redactProxy(p)), dropped: r.dropped, direct_kbps: Math.round(r.dKbps), best_kbps: Math.round(r.bestKbps) });
}

async function gateProxies(url) {
  if (!PROXIES.length && proxySource && autoRefreshEnabled() && !autoRefreshed) await refreshProxyList('empty');
  if (!PROXIES.length) return;
  let r = await benchAndFilter(url);
  if (!PROXIES.length && proxySource && autoRefreshEnabled() && !autoRefreshed) {
    emit({ event: 'proxies', kept: [], dropped: r.total, direct_kbps: Math.round(r.dKbps), best_kbps: Math.round(r.bestKbps) });
    await refreshProxyList('all-dead');
    if (PROXIES.length) r = await benchAndFilter(url);
  }
  reportBench(r);
}

async function sha256File(p) {
  const h = crypto.createHash('sha256');
  await new Promise((res, rej) => {
    const rs = fs.createReadStream(p);
    rs.on('data', (c) => h.update(c));
    rs.on('end', res);
    rs.on('error', rej);
  });
  return h.digest('hex');
}

// post-download verification; bad output (+parts) is deleted so a rerun starts clean
async function verifyOutput(outPath, tmpDir) {
  const bytes = fs.existsSync(outPath) ? fs.statSync(outPath).size : 0;
  const bad = async (msg) => {
    try { fs.unlinkSync(outPath); } catch {}
    if (tmpDir) { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {} }
    emit({ event: 'error', scope: 'verify', message: msg });
    throw new Error(msg);
  };
  if (EXPECT_SIZE && bytes !== EXPECT_SIZE) await bad(`size mismatch: got ${fmtSize(bytes)}, expected ${fmtSize(EXPECT_SIZE)} (bad output deleted)`);
  let sha = null;
  if (EXPECT_SHA) {
    say('Verifying sha256...');
    sha = await sha256File(outPath);
    if (sha.toLowerCase() !== EXPECT_SHA) await bad(`sha256 mismatch: got ${sha}, expected ${EXPECT_SHA} (bad output deleted)`);
    say('sha256 OK');
  }
  return { bytes, sha: sha || null };
}

async function runDownload(targetUrl) {
  let info = null;
  for (let pf = 1; ; pf++) {
    try { info = await getFileInfo(targetUrl); break; }
    catch (e) {
      const permanent = (e && e.fatal) || (/HTTP 4\d\d/.test(e.message) && !/HTTP (429|408)/.test(e.message));
      if (permanent || pf > MAX_RETRIES) {
        emit({ event: 'error', scope: 'probe', message: e.message });
        throw new Error('Probe failed: ' + e.message);
      }
      emit({ event: 'retry', scope: 'probe', fails: pf, after_ms: Math.round(backoffMs(pf)) });
      await backoff(pf); // transient network blip: keep trying until the file is reachable
    }
  }
  const mainStart = Date.now();
  const doneStats = (bytes) => {
    const secs = (Date.now() - mainStart) / 1000;
    return { secs: +secs.toFixed(1), bps: Math.round(bytes / Math.max(secs, 0.01)) };
  };
  const url = info.finalUrl;
  const baseName = opts.output || info.filename || path.basename(new URL(url).pathname) || 'download.bin';
  let outPath = baseName;
  if (opts.dir && !opts.output) {
    fs.mkdirSync(path.resolve(opts.dir), { recursive: true });
    outPath = path.join(path.resolve(opts.dir), path.basename(baseName));
  }
  if (info.html) {
    warn('Server returned a web page (text/html), not a file. Your link is probably expired or points at a preview/share page. Get a fresh direct link and retry.');
  }
  const SOURCES = [url, ...(opts.mirror || [])];
  await gateProxies(url);
  const infoLine = `Size: ${fmtSize(info.size)} | Range: ${info.range ? 'yes' : 'no'} | Conn: ${CONNECTIONS} | Sources: ${SOURCES.length} | Proxies: ${PROXIES.length}${proxySource ? ` (${proxySource})` : ''}`;
  say(infoLine);
  emit({ event: 'start', url: displayUrl(url, true), output: outPath, size: info.size || 0, range: !!info.range, connections: CONNECTIONS, sources: SOURCES.length, proxies: PROXIES.length });
  // fail fast before spending bandwidth
  const guardFail = (msg) => { emit({ event: 'error', scope: 'guard', message: msg }); throw new Error(msg); };
  const PROTECTED_NAMES = new Set(['proxies.txt', 'agent-dla.json', 'get-proxies.js', 'agent-dla.js', 'package.json', 'package-lock.json']);
  if (!opts.output && PROTECTED_NAMES.has(path.basename(outPath).toLowerCase())) {
    guardFail(`refusing: server filename "${path.basename(outPath)}" collides with a tool file (use -o to choose a name)`);
  }
  if (EXPECT_SIZE && info.size && info.size !== EXPECT_SIZE) guardFail(`size mismatch: server says ${fmtSize(info.size)}, expected ${fmtSize(EXPECT_SIZE)}`);
  if (MAX_SIZE && info.size && info.size > MAX_SIZE) guardFail(`refusing: server size ${fmtSize(info.size)} exceeds --max-size ${fmtSize(MAX_SIZE)}`);
  if (EXPECT_TYPE && info.mime && info.mime !== EXPECT_TYPE) guardFail(`type mismatch: server says ${info.mime}, expected ${EXPECT_TYPE}`);
  if (fs.existsSync(outPath) && info.size && fs.statSync(outPath).size === info.size) {
    if (EXPECT_SHA) {
      say('Found complete file, verifying sha256...');
      const got = await sha256File(outPath);
      if (got.toLowerCase() !== EXPECT_SHA) {
        say('sha256 mismatch on existing file, redownloading...');
        try { fs.unlinkSync(outPath); } catch {}
        try { fs.rmSync(outPath + '.parts', { recursive: true, force: true }); } catch {}
      } else {
        emit({ event: 'done', output: path.resolve(outPath), bytes: info.size, seconds: 0, speed_bps: 0, sha256: got, cached: true });
        say(`Already complete -> ${path.resolve(outPath)}`);
        return info.size;
      }
    } else {
      emit({ event: 'done', output: path.resolve(outPath), bytes: info.size, seconds: 0, speed_bps: 0, sha256: null, cached: true });
      say(`Already complete -> ${path.resolve(outPath)}`);
      return info.size;
    }
  }

  if (!info.range || !info.size || CONNECTIONS === 1) {
    say(info.range ? 'Single connection fallback.' : 'Server ignores Range, single-stream download.');
    shutdownHandler = (sig) => { console.error(`\nInterrupted (${sig}). Partial kept at ${outPath} — rerun to resume.`); process.exit(130); };
    let singleFails = 0;
    while (true) {
      try {
        await downloadSingle(url, outPath, nextProxy(), info.size);
        break;
      } catch (e) {
        const cls = classifyErr(e);
        if (cls === 'fatal') { emit({ event: 'error', scope: 'single', message: e.message }); throw e; }
        singleFails++;
        if (singleFails > MAX_RETRIES) {
          emit({ event: 'error', scope: 'single', message: e.message });
          throw new Error(`single-stream failed ${MAX_RETRIES}x: ${e.message} (partial kept at ${outPath}, rerun to resume)`);
        }
        const waitMs = (cls === 'throttle' && e.retryAfter > 0) ? Math.min(e.retryAfter, 120) * 1000 : backoffMs(singleFails);
        emit({ event: 'retry', scope: 'single', fails: singleFails, after_ms: Math.round(waitMs), throttled: cls === 'throttle' });
        say(`Single-stream interrupted (${e.message}), retrying...`);
        await sleep(waitMs);
      }
    }
    const v1 = await verifyOutput(outPath, null);
    shutdownHandler = null;
    const st1 = doneStats(v1.bytes);
    emit({ event: 'done', output: path.resolve(outPath), bytes: v1.bytes, seconds: st1.secs, speed_bps: st1.bps, sha256: v1.sha });
    say(`Saved -> ${path.resolve(outPath)}`);
    return v1.bytes;
  }

  const size = info.size;
  const n = Math.min(CONNECTIONS, size);
  const chunkSize = Math.floor(size / n);
  const tmpDir = outPath + '.parts';
  fs.mkdirSync(tmpDir, { recursive: true });
  for (const f of fs.readdirSync(tmpDir)) { // leftovers from kills: .tmp is never valid input
    if (f.endsWith('.tmp')) { try { fs.unlinkSync(path.join(tmpDir, f)); } catch {} }
  }

  const jobs = [];
  for (let i = 0; i < n; i++) {
    const start = i * chunkSize;
    const end = (i === n - 1) ? size - 1 : (i + 1) * chunkSize - 1;
    jobs.push({ i, start, end, part: path.join(tmpDir, `part${i}`), src: SOURCES[i % SOURCES.length] });
  }

  let doneBytes = 0; const t0 = Date.now();
  const active = new Map(); // job.i -> bytes downloaded in current attempt
  let pending = 0, totalRetries = 0, lastJsonEmit = 0;
  const liveBytes = () => {
    let s = doneBytes;
    for (const v of active.values()) s += v;
    return s;
  };
  const draw = () => {
    const el = (Date.now() - t0) / 1000;
    const cur = liveBytes();
    const pct = (cur / size * 100).toFixed(1);
    const spd = el ? (cur / 1024 / 1024 / el) : 0;
    const eta = spd > 0.001 ? ((size - cur) / 1024 / 1024 / spd).toFixed(0) : '?';
    if (!JSON_MODE) process.stdout.write(`\r${pct}% ${fmtSize(cur)}/${fmtSize(size)} ${spd.toFixed(2)} MB/s ETA ${eta}s | chunks ${jobs.length - pending}/${jobs.length} active ${active.size} retries ${totalRetries} splits ${splitCount}  `);
    if (JSON_MODE && Date.now() - lastJsonEmit >= 1000) {
      lastJsonEmit = Date.now();
      emit({
        event: 'progress', bytes_done: cur, total: size,
        speed_bps: Math.round(spd * 1048576), eta_s: spd > 0.001 ? Math.round((size - cur) / 1048576 / spd) : null,
        chunks_done: jobs.length - pending, chunks_total: jobs.length, active: active.size, retries: totalRetries, splits: splitCount,
      });
    }
  };
  const timer = setInterval(draw, 250);

  // straggler mitigation: split a stalled chunk so faster workers take half
  const inflight = new Map(); // job.i -> { job, t0, token }
  const SPLIT_MIN_REMAIN = 2 * 1048576;
  // test hooks (env): shorten stall detection in the test suite; defaults shown
  const SPLIT_STALL_S = Math.max(parseFloat(process.env.AGENT_DLA_SPLIT_STALL_S) || 20, 1);
  const SPLIT_COOLDOWN_S = Math.max(parseFloat(process.env.AGENT_DLA_SPLIT_COOLDOWN_S) || 20, 1);
  let splitCount = 0;
  let splitBudget = 0;
  function splitStragglers() {
    if (fatal || pending === 0) return;
    const el = (Date.now() - t0) / 1000;
    if (el < 5) return;
    const overall = liveBytes() / Math.max(el, 0.01);
    const floor = Math.max(51200, overall * 0.25);
    for (const [, f] of inflight) {
      const { job, t0: jt, token } = f;
      const age = (Date.now() - jt) / 1000;
      if (age < SPLIT_STALL_S) continue;
      if ((job.splits || 0) >= 3 || splitCount >= splitBudget) continue;
      if (Date.now() - (job.lastSplit || 0) < SPLIT_COOLDOWN_S * 1000) continue;
      const got = active.get(job.i) || 0;
      const speed = got / Math.max(age, 0.01);
      const remain = job.end - job.start + 1;
      if (speed >= floor || remain < SPLIT_MIN_REMAIN) continue;
      const mid = job.start + Math.floor((remain - 1) / 2);
      const half = { i: jobs.length, start: mid + 1, end: job.end, part: path.join(tmpDir, `part${jobs.length}`), src: SOURCES[jobs.length % SOURCES.length], splits: 0 };
      job.end = mid;
      job.splits = (job.splits || 0) + 1;
      job.lastSplit = Date.now();
      jobs.push(half);
      queue.push(half);
      pending++;
      splitCount++;
      active.set(half.i, 0);
      try { if (token && token.req) { const e = new Error('split straggler'); e.code = 'SPLIT'; token.req.destroy(e); } } catch {}
      emit({ event: 'split', chunk: job.i, new_chunk: half.i, at: mid, speed_bps: Math.round(speed) });
      say(`Splitting stalled chunk ${job.i} at ${fmtSize(mid - job.start + 1)} (was ${fmtSize(remain)} @ ${(speed / 1024).toFixed(0)} KB/s)`);
    }
  }
  const splitTimer = setInterval(splitStragglers, 2000);

  // returns true on success, false to requeue, { fatal } to abort everything
  async function runJob(job) {
    const ATTEMPTS = Math.min(Math.max(RETRIES + 1, PROXIES.length || 0), 16);
    const track = (d) => active.set(job.i, (active.get(job.i) || 0) + d);
    const finishAttempt = (okBytes) => {
      inflight.delete(job.i);
      active.delete(job.i);
      if (okBytes) {
        doneBytes += okBytes;
        emit({ event: 'chunk-done', chunk: job.i, bytes: okBytes, resumed: false, via: job.lastVia || 'direct' });
      }
    };
    for (let a = 0; a < ATTEMPTS; a++) {
      const proxy = nextProxy();
      const token = {};
      active.set(job.i, 0);
      inflight.set(job.i, { job, t0: Date.now(), token });
      try {
        if (fs.existsSync(job.part)) {
          const st = fs.statSync(job.part);
          const expect = job.end - job.start + 1;
          if (st.size === expect) { doneBytes += st.size; inflight.delete(job.i); active.delete(job.i); emit({ event: 'chunk-done', chunk: job.i, bytes: st.size, resumed: true }); return true; } // resume
          fs.unlinkSync(job.part); // stale layout (different -n): redownload whole range
        }
        job.lastVia = redactProxy(proxy);
        await downloadChunkToFile(job.src, job.start, job.end, job.part + '.tmp', proxy, track, token);
        fs.renameSync(job.part + '.tmp', job.part);
        finishAttempt(job.end - job.start + 1);
        return true;
      } catch (e) {
        inflight.delete(job.i);
        active.delete(job.i);
        try { if (fs.existsSync(job.part + '.tmp')) fs.unlinkSync(job.part + '.tmp'); } catch {}
        const cls = classifyErr(e);
        if (cls === 'split') return 'split';
        if (cls === 'fatal') return { fatal: e };
        if (cls === 'throttle' && e.retryAfter > 0) {
          say(`Chunk ${job.i} throttled (HTTP ${e.status}), waiting ${e.retryAfter}s...`);
          await sleep(Math.min(e.retryAfter, 120) * 1000);
        }
      }
    }
    // last resort each round: direct connection
    const token = {};
    active.set(job.i, 0);
    inflight.set(job.i, { job, t0: Date.now(), token });
    try {
      job.lastVia = 'direct';
      await downloadChunkToFile(job.src, job.start, job.end, job.part + '.tmp', null, track, token);
      fs.renameSync(job.part + '.tmp', job.part);
      finishAttempt(job.end - job.start + 1);
      return true;
    } catch (e) {
      inflight.delete(job.i);
      active.delete(job.i);
      try { if (fs.existsSync(job.part + '.tmp')) fs.unlinkSync(job.part + '.tmp'); } catch {}
      const cls = classifyErr(e);
      if (cls === 'split') return 'split';
      if (cls === 'fatal') return { fatal: e };
      return false;
    }
  }

  // limit simultaneous sockets to n but avoid EMFILE: cap at 32 concurrent file writes is fine on win
  const CONC = Math.min(n, 32);
  const queue = [...jobs];
  pending = jobs.length;
  splitBudget = jobs.length * 2;
  let fatal = null;
  let down = false;
  shutdownHandler = async (sig) => {
    if (down) return;
    down = true;
    clearInterval(timer);
    clearInterval(splitTimer);
    for (const [, f] of inflight) { try { if (f.token && f.token.req) f.token.req.destroy(); } catch {} }
    await sleep(500); // let in-flight catches unlink their .tmp
    for (const j of jobs) { try { fs.unlinkSync(j.part + '.tmp'); } catch {} }
    console.error(`\nInterrupted (${sig}). ${jobs.length - pending}/${jobs.length} chunks done, parts kept in ${tmpDir} — rerun the same command to resume.`);
    process.exit(130);
  };
  const workers = Array.from({ length: CONC }, async () => {
    while (true) {
      const j = queue.shift();
      if (!j) { if (pending === 0 || fatal || down) return; await sleep(500); continue; }
      const r = await runJob(j);
      if (down) return;
      if (r === true) { pending--; continue; }
      if (r === 'split') { queue.push(j); continue; } // first half still pending, requeue it
      if (r && r.fatal) {
        fatal = new Error(`chunk ${j.i} unrecoverable: ${r.fatal.message} (parts kept in ${tmpDir}, rerun resumes what completed)`);
        pending = 0;
        return;
      }
      j.fails = (j.fails || 0) + 1;
      totalRetries++;
      emit({ event: 'retry', scope: 'chunk', chunk: j.i, fails: j.fails, after_ms: Math.round(backoffMs(j.fails)) });
      if (j.fails > MAX_RETRIES) {
        fatal = new Error(`chunk ${j.i} failed ${MAX_RETRIES}x (parts kept in ${tmpDir}, rerun to resume)`);
        pending = 0;
        return;
      }
      await backoff(j.fails);
      if (fatal || down) return;
      queue.push(j);
    }
  });
  await Promise.all(workers);
  if (fatal) { clearInterval(timer); clearInterval(splitTimer); throw fatal; }
  clearInterval(timer);
  clearInterval(splitTimer);
  if (JSON_MODE) {
    const elFin = (Date.now() - t0) / 1000;
    emit({
      event: 'progress', bytes_done: size, total: size,
      speed_bps: Math.round(size / Math.max(elFin, 0.01)), eta_s: 0,
      chunks_done: jobs.length, chunks_total: jobs.length, active: 0, retries: totalRetries,
    });
  }
  say('Merging...');

  const ws = fs.createWriteStream(outPath);
  for (const j of [...jobs].sort((a, b) => a.start - b.start)) {
    await new Promise((res, rej) => {
      const rs = fs.createReadStream(j.part);
      rs.pipe(ws, { end: false });
      rs.on('end', res); rs.on('error', rej);
    });
  }
  ws.end();
  await new Promise(r => ws.on('finish', r));
  const v = await verifyOutput(outPath, tmpDir);
  shutdownHandler = null;
  fs.rmSync(tmpDir, { recursive: true, force: true });
  const el = (Date.now() - t0) / 1000;
  emit({ event: 'done', output: path.resolve(outPath), bytes: size, seconds: +el.toFixed(1), speed_bps: Math.round(size / Math.max(el, 0.1)), sha256: v.sha });
  say(`Saved -> ${path.resolve(outPath)} (${(size / 1048576).toFixed(2)} MB in ${el.toFixed(1)}s, ${(size / 1024 / 1024 / Math.max(el, 0.1)).toFixed(2)} MB/s)`);
  return size;
}

(async () => {
  if (program.args.length > 1) { console.error('only one URL argument allowed; use --list for batch'); process.exit(2); }
  const urlArg = program.args[0];
  if (urlArg && !validTarget(urlArg)) { console.error(`invalid URL (want http(s)): ${displayUrl(urlArg, false)}`); process.exit(2); }
  const targets = [...(urlArg ? [urlArg] : []), ...loadList(opts.list)];
  if (!targets.length) { console.error('URL or --list required'); process.exit(2); }
  if (targets.length > 1) {
    if (opts.output) { console.error('--output with multiple URLs is ambiguous; use --dir'); process.exit(2); }
    if ((opts.mirror || []).length) { console.error('--mirror with multiple URLs is unsafe (mirrors must serve the same file)'); process.exit(2); }
    if (opts.sha256 || opts.expectSize) { console.error('--sha256/--expect-size need a single download'); process.exit(2); }
  }
  emit({ event: 'batch', files: targets.length });
  const bt0 = Date.now();
  let bytes = 0;
  const failed = [];
  for (const t of targets) {
    if (!validTarget(t)) {
      const msg = 'skipping invalid URL (want http(s))';
      failed.push(displayUrl(t, true));
      emit({ event: 'error', scope: 'file', url: displayUrl(t, true), message: msg });
      console.error(`FAILED ${displayUrl(t, false)}: ${msg}`);
      continue;
    }
    try { bytes += await runDownload(t); }
    catch (e) {
      failed.push(displayUrl(t, true));
      emit({ event: 'error', scope: 'file', url: displayUrl(t, true), message: e.message });
      console.error(`FAILED ${displayUrl(t, false)}: ${e.message}`);
    }
    shutdownHandler = null;
  }
  const bsecs = (Date.now() - bt0) / 1000;
  emit({ event: 'batch-done', files: targets.length, completed: targets.length - failed.length, failed, bytes, seconds: +bsecs.toFixed(1) });
  if (failed.length) { console.error(`${failed.length}/${targets.length} failed`); process.exit(1); }
})().catch(e => { emit({ event: 'error', message: e.message }); console.error(e.message); process.exit(1); });
