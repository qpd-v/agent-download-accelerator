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
const { pipeline } = require('stream');
const { promisify } = require('util');
const pipelineAsync = promisify(pipeline);

function collect(v, arr) { arr.push(v); return arr; }

program
  .name('agent-dla')
  .description('Agent Download Accelerator: parallel Range chunks, mirrors, proxy rotation, resume')
  .version(require('./package.json').version, '-V, --version', 'print the version')
  .argument('[url]', 'file URL to download (or use --list)')
  .option('-o, --output <file>', 'output file path')
  .option('--dir <folder>', 'download into this folder (created if needed)')
  .option('--list <file>', 'batch mode: one URL per line (# comments allowed)')
  .option('--config <file>', 'config file (default: ./agent-dla.json if present)')
  .option('-n, --connections <n>', 'parallel connections (chunks), default 8, max 128 (at most 32 transfer concurrently)', '8')
  .option('-p, --proxies <file>', 'proxy list file (default: ./proxies.txt if present)')
  .option('--mirror <url>', 'mirror URL serving the identical file (repeatable)', collect, [])
  .option('--timeout <ms>', 'per-request timeout ms', '15000')
  .option('--retries <n>', 'retries per chunk', '3')
  .option('--max-retries <n>', 'requeue rounds per chunk before aborting (parts are kept, rerun resumes)', '100')
  .option('--deadline <ms>', 'abort the whole download after this long (0 = none)')
  .option('--sha256 <hex>', 'verify file sha256 after download (bad output is deleted)')
  .option('--expect-size <size>', 'fail if final size differs (e.g. 10MB, 1.5GB, 1048576)')
  .option('--max-size <size>', 'refuse before / abort above this size')
  .option('--expect-type <mime>', 'fail if server content-type differs')
  .option('-k, --insecure', 'allow self-signed certs')
  .option('--no-auto-refresh', 'never auto-refresh the proxy list (default: refresh once when empty or all dead)')
  .option('--overwrite', 'allow overwriting an existing file chosen by the server (explicit -o always allows)')
  .option('--allow-html', 'save text/html responses instead of refusing')
  .option('--json', 'newline-delimited JSON events on stdout (human logs go to stderr)')
  .option('--redact', 'redact URL queries/credentials in human logs too (JSON events are always redacted)')
  .option('--header <h>', 'extra request header "Name: value" (repeatable; dropped on cross-origin redirect)', collect, [])
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
  const explicit = !!opts.config;
  const p = opts.config || (fs.existsSync(path.resolve('agent-dla.json')) ? path.resolve('agent-dla.json') : null);
  if (!p) return;
  let cfg;
  try { cfg = JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch (e) { console.error(`bad config ${p}: ${e.message}`); process.exit(2); }
  const cli = (name) => program.getOptionValueSource(name) === 'cli';
  // Sensitive keys are only honored from an explicit --config. An agent-dla.json
  // sitting in the working directory could come from an untrusted checkout.
  const blocked = [];
  const sensitive = (key, apply) => {
    if (explicit) apply();
    else blocked.push(key);
  };
  if (!cli('connections') && cfg.connections !== undefined) opts.connections = String(cfg.connections);
  if (!cli('timeout') && cfg.timeout !== undefined) opts.timeout = String(cfg.timeout);
  if (!cli('retries') && cfg.retries !== undefined) opts.retries = String(cfg.retries);
  if (!cli('maxRetries') && cfg.maxRetries !== undefined) opts.maxRetries = String(cfg.maxRetries);
  if (!cli('deadline') && cfg.deadline !== undefined) opts.deadline = String(cfg.deadline);
  if (!cli('proxies') && cfg.proxies) sensitive('proxies', () => {
    opts.proxies = !path.isAbsolute(cfg.proxies) ? path.join(path.dirname(p), cfg.proxies) : cfg.proxies;
  });
  if (!cli('mirror') && Array.isArray(cfg.mirrors) && cfg.mirrors.length) sensitive('mirrors', () => { opts.mirror = cfg.mirrors; });
  if (!cli('dir') && cfg.outputDir) sensitive('outputDir', () => { opts.dir = cfg.outputDir; });
  if (!cli('header') && Array.isArray(cfg.headers) && cfg.headers.length) sensitive('headers', () => { opts.header = cfg.headers.map(String); });
  if (!cli('json') && cfg.json) opts.json = true;
  if (!cli('insecure') && cfg.insecure) sensitive('insecure', () => { opts.insecure = true; });
  if (program.getOptionValueSource('autoRefresh') !== 'cli' && (cfg.autoRefresh === false || cfg.noAutoRefresh === true)) opts.autoRefresh = false;
  if (cfg.harvestTimeout) HARVEST_TIMEOUT_MS = parseInt(cfg.harvestTimeout, 10) || 0;
  if (cfg.harvestScript) sensitive('harvestScript', () => {
    HARVEST_SCRIPT = path.isAbsolute(cfg.harvestScript) ? cfg.harvestScript : path.join(path.dirname(p), cfg.harvestScript);
  });
  if (program.getOptionValueSource('redact') !== 'cli' && cfg.redact) opts.redact = true;
  if (program.getOptionValueSource('overwrite') !== 'cli' && cfg.overwrite) opts.overwrite = true;
  if (program.getOptionValueSource('allowHtml') !== 'cli' && cfg.allowHtml) opts.allowHtml = true;
  if (blocked.length) console.error(`WARNING: ignoring sensitive config keys from auto-loaded ${p} (use --config to allow): ${blocked.join(', ')}`);
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
function numOpt(v, def, min, max) {
  if (v === undefined || v === null || v === '') return def;
  const n = parseInt(v, 10);
  if (isNaN(n)) return def;
  return Math.min(Math.max(n, min), max);
}
const CONNECTIONS = numOpt(opts.connections, 8, 1, 128);
const BENCH_CONC = Math.min(CONNECTIONS, 32);
const TIMEOUT = numOpt(opts.timeout, 15000, 1, 3600000);
const RETRIES = numOpt(opts.retries, 3, 0, 64);
const MAX_RETRIES = numOpt(opts.maxRetries, 100, 0, 1000);
const DEADLINE_MS = numOpt(opts.deadline, 0, 0, 86400000);
let DL_AT = 0; // per-file deadline timestamp, set in the batch loop
let DL_FIRED = false; // set by the deadline timer; data handlers cancel in-flight requests
let dlTimer = null;
const DL_REQS = new Set(); // live request objects, destroyed when the deadline fires
function deadlineErr() { return Object.assign(new Error('deadline exceeded'), { fatal: true }); }
function trackReq(req) {
  DL_REQS.add(req);
  req.on('close', () => DL_REQS.delete(req));
  return req;
}
function checkDeadline() {
  if (DL_FIRED || (DL_AT && Date.now() > DL_AT)) { const e = new Error('deadline exceeded'); e.fatal = true; throw e; }
}
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
const ALLOW_HTML = !!opts.allowHtml;
const usedOutputs = new Set(); // outputs claimed by this process (batch uniqueness)
// Exclusive per-output lock (N2): two processes writing one output would share
// its .partial/manifest. `<out>.partial.lock` holds the owner's pid, created
// with O_EXCL. A lock whose pid is gone is stale (crash/kill) and is taken over.
// A reused pid looks alive: the error names the lock file so a human can clear it.
const heldLocks = new Set();
// Resuming without ETag/Last-Modified cannot prove the file is unchanged: a
// same-size republish would mix versions. Only a checksum catches that.
let warnedNoValidator = false;
function warnNoValidator() {
  if (warnedNoValidator || EXPECT_SHA) return;
  warnedNoValidator = true;
  warn('resuming from a server that sends no ETag or Last-Modified: a republished file of the same size cannot be detected. Use --sha256 to verify the result.');
}
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return !!(e && e.code === 'EPERM'); }
}
function acquireOutputLock(outPath) {
  const lockPath = path.resolve(outPath) + '.partial.lock';
  if (heldLocks.has(lockPath)) return null; // same process re-entering (fresh/stale restart)
  const release = () => {
    heldLocks.delete(lockPath);
    // Remove only a lock that still names this process (never a successor's).
    try { if (parseInt(fs.readFileSync(lockPath, 'utf8'), 10) === process.pid) fs.unlinkSync(lockPath); } catch {}
  };
  // The lock must never be visible empty: write the pid to a private temp file
  // and hard-link it into place (atomic; EEXIST if held). Filesystems without
  // hard links fall back to O_EXCL create + write.
  const tmp = `${lockPath}.${process.pid}.${Date.now()}.tmp`;
  const create = () => {
    try {
      fs.writeFileSync(tmp, String(process.pid));
      try { fs.linkSync(tmp, lockPath); return true; }
      catch (e) {
        if (e.code === 'EEXIST') return false;
        const fd = fs.openSync(lockPath, 'wx'); // no hard links here
        try { fs.writeSync(fd, String(process.pid)); }
        catch (we) { fs.closeSync(fd); try { fs.unlinkSync(lockPath); } catch {} throw we; }
        fs.closeSync(fd);
        return true;
      }
    } finally { try { fs.unlinkSync(tmp); } catch {} }
  };
  const sleepMs = (ms) => { try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch {} };
  const busy = (pid) => {
    const err = new Error(`another agent-dla (pid ${pid}) is already writing "${path.basename(outPath)}" (if not, delete ${lockPath})`);
    err.fatal = true;
    return err;
  };
  const readPid = () => { try { return parseInt(fs.readFileSync(lockPath, 'utf8'), 10); } catch (re) { return re.code === 'ENOENT' ? null : NaN; } };
  const breaker = lockPath + '.break';
  for (let attempt = 0; attempt < 8; attempt++) {
    let made;
    try { made = create(); }
    catch (e) {
      if (e.code === 'EEXIST') made = false;
      else { warn(`cannot create output lock (${e.code || e.message}): continuing without one`); return null; }
    }
    if (made) { heldLocks.add(lockPath); return release; }
    const pid = readPid();
    if (pid === null) continue; // vanished: try to create again
    if (pidAlive(pid) && pid !== process.pid) throw busy(pid);
    // Stale (owner gone, or unreadable). Only one process at a time may remove
    // a lock it judged stale: take the break file (O_EXCL), re-check the lock
    // under it, unlink, and create our own before letting anyone else break.
    let bfd = null;
    try { bfd = fs.openSync(breaker, 'wx'); }
    catch (e) {
      if (e.code === 'EEXIST') {
        try { if (Date.now() - fs.statSync(breaker).mtimeMs > 10000) fs.unlinkSync(breaker); } catch {} // abandoned breaker
        sleepMs(20 + Math.floor(Math.random() * 30));
        continue;
      }
      warn(`cannot create output lock (${e.code || e.message}): continuing without one`);
      return null;
    }
    try {
      fs.closeSync(bfd);
      const again = readPid();
      if (again !== null && pidAlive(again) && again !== process.pid) throw busy(again); // someone else took it first
      if (again !== null) { try { fs.unlinkSync(lockPath); } catch {} }
      let made2 = false;
      try { made2 = create(); } catch (e) { if (e.code !== 'EEXIST') { warn(`cannot create output lock (${e.code || e.message}): continuing without one`); return null; } }
      if (made2) { heldLocks.add(lockPath); return release; }
    } finally { try { fs.unlinkSync(breaker); } catch {} }
  }
  // Heavy contention on the same output: refuse rather than risk sharing it.
  throw busy('unknown');
}
process.on('exit', () => {
  for (const l of heldLocks) {
    try { if (parseInt(fs.readFileSync(l, 'utf8'), 10) === process.pid) fs.unlinkSync(l); } catch {}
  }
});
const CUSTOM_HEADERS = {};
for (const h of (opts.header || [])) {
  const i = String(h).indexOf(':');
  if (i <= 0) { console.error(`bad --header (want "Name: value"): ${h}`); process.exit(2); }
  const name = h.slice(0, i).trim();
  const value = h.slice(i + 1).trim();
  if (/^(range|user-agent|if-range)$/i.test(name)) { console.error(`--header must not override ${name}`); process.exit(2); }
  if (!value) { console.error(`bad --header (empty value): ${h}`); process.exit(2); }
  if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) { console.error(`bad --header (CR/LF rejected): ${h}`); process.exit(2); }
  CUSTOM_HEADERS[name] = value;
}
// Custom headers are only ever attached to the original URL's origin.
// Redirects, the final URL, mirrors, and bench targets on other origins
// never receive them (bearer tokens must not leak to S3/mirrors/proxies).
let HEADER_ORIGIN = null;
function headersFor(urlStr) {
  try {
    if (HEADER_ORIGIN && new URL(urlStr).origin === HEADER_ORIGIN) return CUSTOM_HEADERS;
  } catch {}
  return {};
}
// Validators for the running chunked download. Immutable for the run: if a
// response disagrees, the file was republished and the run must restart.
let RUN_VALIDATORS = null;
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function msUntilDeadline() {
  if (DL_FIRED) return 0;
  if (!DL_AT) return Infinity;
  return Math.max(0, DL_AT - Date.now());
}
// Every wait races the deadline: a 120 s Retry-After or 31 s backoff must
// not overshoot a 3 s --deadline.
async function sleepOrDeadline(ms) {
  const budget = msUntilDeadline();
  if (budget <= 0) checkDeadline(); // throws
  await sleep(Math.min(ms, budget));
  checkDeadline();
}
function backoffMs(fails) {
  return Math.min(1000 * 2 ** Math.min(fails, 5), 30000) + Math.random() * 1000;
}
async function backoff(fails) { await sleepOrDeadline(backoffMs(fails)); }
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
// URL userinfo (http://user:pw@host) becomes an Authorization header on the
// wire. Through a plain-http proxy that header is visible to the proxy, so
// strip it there (https is CONNECT-tunneled; direct keeps working).
let warnedUserinfo = false;
function requestUrlFor(urlStr, proxyUrl) {
  if (!proxyUrl) return urlStr;
  try {
    const u = new URL(String(urlStr));
    if (u.protocol !== 'http:') return urlStr;
    if (!u.username && !u.password) return urlStr;
    if (!warnedUserinfo) {
      warnedUserinfo = true;
      warn('URL credentials are withheld from plain-http proxy requests (a proxy would see them); use https or a direct connection for authenticated URLs');
    }
    u.username = '';
    u.password = '';
    return u.toString();
  } catch { return urlStr; }
}
function validTarget(t) {
  try {
    const u = new URL(String(t));
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}
// Server-controlled names are hostile input: decode, de-dot, no separators.
function cleanName(name) {
  let out = '';
  for (const ch of String(name)) {
    const c = ch.codePointAt(0);
    if (c < 32 || c === 127 || '\\/;:*?"<>|'.includes(ch)) out += '_';
    else out += ch;
  }
  return out;
}
function sanitizeUrlName(raw) {
  let base = String(raw || '');
  try { base = decodeURIComponent(base); } catch {}
  base = base.split('/').pop().split('\\').pop() || '';
  base = base.replace(/^[\s.]+/, '');
  base = cleanName(base).replace(/[.\s]+$/, '').slice(0, 200);
  if (!base || base === '.' || base === '..') return 'download.bin';
  return base;
}
// Manifest/receipt identity: origin + path + query + size + validator. Query
// parameters that only carry signatures/expiry (presigned URLs) are dropped
// so a refreshed link resumes the same download; everything else (e.g. ?id=1)
// selects content and stays in the key. A shared strong ETag across different
// queries must NOT merge identities: an ETag versions one resource, and a
// different query is a different resource (Q1).
const SIG_QUERY_PARAMS = new Set([
  'signature', 'expires', 'key-pair-id', 'policy',
  'sig', 'se', 'sp', 'sv', 'st', 'sr',
  // NOTE: 'token' is deliberately NOT stripped: ?token= commonly selects the
  // file (download-token endpoints), so stripping it merges identities and
  // yields wrong bytes with exit 0 (T1). Supabase/Firebase refreshed links
  // therefore restart instead of resume — safe (correct bytes), just slower.
]);
function stripSigQuery(search) {
  if (!search || search === '?') return '';
  const kept = [];
  for (const pair of search.slice(1).split('&')) {
    let name = pair.split('=', 1)[0] || '';
    try { name = decodeURIComponent(name).toLowerCase(); }
    catch { name = name.toLowerCase(); }
    if (name.startsWith('x-amz-') || name.startsWith('x-goog-') || SIG_QUERY_PARAMS.has(name)) continue;
    kept.push(pair);
  }
  return kept.length ? `?${kept.join('&')}` : '';
}
function manifestKey(targetUrl, size, etag, mtime) {
  try {
    const u = new URL(String(targetUrl));
    return `${u.origin}${u.pathname}${stripSigQuery(u.search)}|${size}|${etag || ''}|${mtime || ''}`;
  } catch { return `${String(targetUrl)}|${size}|${etag || ''}|${mtime || ''}`; }
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
  if (e instanceof TypeError || e instanceof ReferenceError || e instanceof SyntaxError) return 'fatal'; // programmer error: never retry
  if (e && /^(EISDIR|EACCES|ENOSPC|EPERM|EROFS)$/.test(e.code || '')) return 'fatal';
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
process.on('SIGTERM', () => { if (shutdownHandler) shutdownHandler('SIGTERM'); else process.exit(143); });
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
      .filter((l) => l && !l.startsWith('#'))
      .map((l) => (/^[^:/\s]+:\d{1,5}$/.test(l) ? `http://${l}` : l));
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
  const budget = msUntilDeadline();
  if (budget <= 0) return Promise.resolve(false);
  const timeoutMs = Math.min(
    parseInt(process.env.AGENT_DLA_HARVEST_TIMEOUT_MS || '', 10) || HARVEST_TIMEOUT_MS || 180000,
    budget,
  );
  // Never propagate a TLS bypass into the harvester: it fetches untrusted lists.
  const childEnv = { ...process.env };
  delete childEnv.NODE_TLS_REJECT_UNAUTHORIZED;
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [script, outFile], { timeout: timeoutMs, env: childEnv });
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

const HARVEST_COOLDOWN_MS = 6 * 3600 * 1000;
function harvestMarkerTime(file) {
  try {
    const m = /^# agent-dla auto-refresh (\S+)/.exec(fs.readFileSync(path.resolve(file), 'utf8').split('\n')[0]);
    return m ? Date.parse(m[1]) : NaN;
  } catch { return NaN; }
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
  const marked = harvestMarkerTime(outFile);
  if (!isNaN(marked) && Date.now() - marked < HARVEST_COOLDOWN_MS) {
    say('Proxy list was refreshed recently, not re-harvesting — continuing direct.');
    emit({ event: 'proxies-refresh', phase: 'done', reason, file: outFile, candidates: 0, ok: false, cooldown: true });
    PROXIES = [];
    proxyIdx = 0;
    return;
  }
  try {
    if (fs.existsSync(outFile) && fs.statSync(outFile).size > 0 && !fs.existsSync(`${outFile}.bak`)) {
      fs.copyFileSync(outFile, `${outFile}.bak`);
    }
  } catch {}
  emit({ event: 'proxies-refresh', phase: 'start', reason, file: outFile });
  say(`Proxy list ${reason === 'empty' ? 'is empty' : 'has no working proxies'} — refreshing (${outFile})...`);
  const ok = await runHarvest(outFile);
  PROXIES = ok ? loadProxiesSoft(outFile) : []; // failed harvest: go direct, don't re-bench the known-dead list
  proxyIdx = 0;
  // Marker on every attempt (success or fail): a dead harvest must not
  // re-run for up to 180s on every invocation.
  try {
    const abs = path.resolve(outFile);
    const cur = fs.existsSync(abs) ? fs.readFileSync(abs, 'utf8') : '';
    const stamp = `# agent-dla auto-refresh ${new Date().toISOString()}\n`;
    const stripped = cur.split('\n').filter((l) => !l.startsWith('# agent-dla auto-refresh')).join('\n');
    fs.writeFileSync(abs, stamp + stripped);
  } catch {}
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
  name = cleanName(name).replace(/^[\s.]+/, '').replace(/[.\s]+$/, '').slice(0, 200);
  if (!name || name === '.' || name === '..') return null;
  return name;
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

function agentFor(proxyUrl, targetIsHttps, timeout = TIMEOUT) {
  if (!proxyUrl) return targetIsHttps ? directHttpsAgent : directHttpAgent;
  const low = proxyUrl.toLowerCase();
  if (low.startsWith('socks')) return new SocksProxyAgent(proxyUrl, { timeout, ...TLS_INSECURE });
  return targetIsHttps ? new HttpsProxyAgent(proxyUrl, { timeout, ...TLS_INSECURE }) : new HttpProxyAgent(proxyUrl, { timeout, ...TLS_INSECURE });
}

function requestOnce(urlStr, headers, proxyUrl, depth = 0) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    const agent = agentFor(proxyUrl, isHttps);
    // No custom headers through proxies on plain http: the proxy would see
    // credentials in the clear. (https targets are CONNECT-tunneled.)
    // Same for URL userinfo: strip it so the proxy never sees Authorization.
    const reqUrl = requestUrlFor(urlStr, proxyUrl);
    const req = lib.request(reqUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'agent-dla/1.0', ...(proxyUrl && !isHttps ? {} : headersFor(urlStr)), ...headers },
      agent,
      timeout: TIMEOUT,
      ...TLS_INSECURE,
    }, (res) => {
      let next = null;
      try { next = redirectTarget(res, reqUrl, depth); }
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
      const finish = (body) => { if (!settled) { settled = true; resolve({ status: res.statusCode, headers: res.headers, body, finalUrl: reqUrl }); } };
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
    trackReq(req);
    req.end();
  });
}

const PROBE_RETRIES = 5;
function infoFromProbe(r, url) {
  return { size: 0, range: false, finalUrl: r.finalUrl || url, filename: filenameFromDisposition(r.headers), html: isHtmlType(r.headers), mime: mimeOf(r.headers), etag: r.headers.etag || null, mtime: r.headers['last-modified'] || null };
}
async function getFileInfo(url) {
  // Direct first: fastest signal with no proxy delay. Proxies are tried when
  // direct fails; a direct 4xx is remembered and becomes fatal only if no
  // proxy path succeeds (it usually means the file itself is gone).
  const order = [null, ...PROXIES.slice(0, 32)];
  const rounds = MAX_RETRIES === 0 ? 1 : PROBE_RETRIES;
  let lastErr = new Error('probe failed');
  let directErr = null;
  const probeDead = new Set();
  for (let round = 0; round < rounds; round++) {
    checkDeadline();
    for (const proxy of order) {
      if (proxy !== null && probeDead.has(proxy)) continue;
      let r;
      try {
        r = await requestOnce(url, { Range: 'bytes=0-0' }, proxy);
      } catch (e) {
        lastErr = e;
        if (e && e.fatal) throw e;
        if (e && e.code === 'ENOTFOUND' && round >= 1) { e.fatal = true; throw e; }
        if (proxy !== null) probeDead.add(proxy);
        continue; // transient: next path
      }
      if (r.status === 206) {
        const cr = parseContentRange(r.headers['content-range']);
        if (cr && cr.total > 0) return { ...infoFromProbe(r, url), size: cr.total, range: true };
        return infoFromProbe(r, url); // unknown total: single-stream fallback
      }
      if (r.status === 200) {
        const len = parseInt(r.headers['content-length'] || '0', 10);
        return { ...infoFromProbe(r, url), size: len || 0 };
      }
      if (r.status === 416) {
        // e.g. zero-byte file: retry the probe without Range once
        try {
          const r2 = await requestOnce(url, {}, proxy);
          if (r2.status === 200) {
            const len = parseInt(r2.headers['content-length'] || '0', 10);
            return { ...infoFromProbe(r2, url), size: len || 0 };
          }
        } catch (e) { lastErr = e; continue; }
      }
      lastErr = new Error(`probe via ${redactProxy(proxy)}: HTTP ${r.status}`);
      lastErr.status = r.status;
      lastErr.retryAfter = parseRetryAfter(r.headers || {});
      if (proxy === null && r.status >= 400 && r.status < 500 && r.status !== 408 && r.status !== 429) {
        directErr = lastErr;
        directErr.fatal = true;
      }
      // proxy-path 4xx only condemns that path; other paths are still tried
    }
    if (round + 1 < rounds) await sleepOrDeadline(Math.min(1000 * 2 ** round, 8000));
    if (directErr && order.length <= 1) break; // direct-only: no other path can save it
  }
  throw directErr || lastErr;
}

function parseContentRange(v) {
  const m = /^\s*bytes\s+(\d+)-(\d+)\/(\d+|\*)\s*$/i.exec(String(v || ''));
  if (!m) return null;
  return { start: parseInt(m[1], 10), end: parseInt(m[2], 10), total: m[3] === '*' ? NaN : parseInt(m[3], 10) };
}
function writeAll(fd, buf, pos) {
  let off = 0;
  while (off < buf.length) {
    const n = fs.writeSync(fd, buf, off, buf.length - off, pos + off);
    if (n <= 0) throw new Error('short write');
    off += n;
  }
}
// Streaming range download straight into the shared output fd at absolute
// positions. No part files: received bytes are already correctly placed,
// so splits and kills never discard or misplace data.
function downloadRange(url, start, end, fd, proxyUrl, onProgress, token, depth = 0, expectTotal = 0, ifRange = null, expectValidator = null) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    const agent = agentFor(proxyUrl, isHttps);
    const rangeHeaders = { 'User-Agent': 'agent-dla/1.0', ...(proxyUrl && !isHttps ? {} : headersFor(url)), Range: `bytes=${start}-${end}` };
    if (ifRange) rangeHeaders['If-Range'] = ifRange;
    const reqUrl = requestUrlFor(url, proxyUrl);
    const req = lib.request(reqUrl, {
      method: 'GET',
      headers: rangeHeaders,
      agent,
      timeout: TIMEOUT,
      ...TLS_INSECURE,
    }, (res) => {
      let next = null;
      try { next = redirectTarget(res, reqUrl, depth); }
      catch (e) { res.resume(); reject(e); return; }
      if (next) {
        res.resume();
        downloadRange(next, start, end, fd, proxyUrl, onProgress, token, depth + 1, expectTotal, ifRange, expectValidator).then(resolve, reject);
        return;
      }
      const expected = end - start + 1;
      if (res.statusCode === 412) {
        try { res.destroy(); } catch {}
        const e = new Error('file changed mid-download (If-Range mismatch)');
        e.fatal = true;
        e.code = 'CHANGED';
        reject(e);
        return;
      }
      if (res.statusCode !== 206) {
        try { res.destroy(); } catch {}
        const e = httpError(res.statusCode, res.headers, `${start}-${end}`);
        if (res.statusCode === 200) {
          // The range was ignored (weak/missing If-Range yields 200, not 412
          // per RFC 9110), so this attempt's bytes prove nothing. Handled as
          // STALE upstream: mirrors get evicted, the direct primary falls
          // back to single-stream.
          e.message += ' (server ignored Range for chunk)';
          e.rangeInvalid = true;
          e.code = 'STALE_RANGE';
        }
        reject(e);
        return;
      }
      const cr = parseContentRange(res.headers['content-range']);
      if (!cr || cr.start !== start || cr.end !== end || (expectTotal > 0 && cr.total !== expectTotal)) {
        try { res.destroy(); } catch {}
        const e = new Error(`Content-Range mismatch for chunk ${start}-${end}: got ${res.headers['content-range'] || 'none'}`);
        e.fatal = true;
        e.rangeInvalid = true;
        reject(e);
        return;
      }
      // Version check is primary-only: mirrors legitimately carry their own
      // ETags. A mismatch means the file was republished mid-download.
      if (expectValidator) {
        const re = res.headers.etag;
        const rm = res.headers['last-modified'];
        if ((expectValidator.etag && re && re !== expectValidator.etag)
          || (expectValidator.mtime && rm && rm !== expectValidator.mtime)) {
          try { res.destroy(); } catch {}
          const e = new Error('file version changed mid-download (validator mismatch)');
          e.fatal = true;
          e.code = 'CHANGED';
          reject(e);
          return;
        }
      }
      let pos = start;
      let received = 0;
      let failed = false;
      const fail = (e) => { if (!failed) { failed = true; try { req.destroy(); } catch {} reject(e); } };
      res.on('data', (c) => {
        if (failed) return;
        if (DL_FIRED) { fail(Object.assign(new Error('deadline exceeded'), { fatal: true })); return; }
        if (pos + c.length > end + 1) {
          const e = new Error(`chunk ${start}-${end} overran`);
          e.fatal = true;
          fail(e);
          return;
        }
        try {
          writeAll(fd, c, pos);
        } catch (e) { try { res.destroy(); } catch {} fail(e); return; }
        pos += c.length;
        received += c.length;
        if (onProgress) onProgress(c.length);
      });
      res.on('end', () => {
        if (failed) return;
        if (received !== expected) { fail(new Error(`short chunk ${start}-${end}: got ${received} of ${expected}`)); return; }
        resolve(received);
      });
      res.on('error', fail);
    });
    if (token) token.req = req;
    const timeoutErr = new Error('timeout');
    timeoutErr.code = 'TIMEOUT';
    req.on('timeout', () => req.destroy(timeoutErr));
    req.on('error', reject);
    trackReq(req);
    req.end();
  });
}
async function downloadSingle(url, outPath, proxyUrl, totalSize, depth = 0, sideKey = null, validators = null, state = null) {
  const u = new URL(url);
  const isHttps = u.protocol === 'https:';
  const lib = isHttps ? https : http;
  const partialPath = outPath + '.partial';
  const sidecarPath = outPath + '.single.json';
  const readSidecar = () => { try { const s = JSON.parse(fs.readFileSync(sidecarPath, 'utf8')); return s && typeof s === 'object' ? s : null; } catch { return null; } };
  const writeSidecar = () => { try { fs.writeFileSync(sidecarPath, JSON.stringify({ key: sideKey })); } catch {} };
  const truncate = () => { try { fs.unlinkSync(partialPath); } catch {} try { fs.unlinkSync(sidecarPath); } catch {} };
  // Resume only a download this tool started (sidecar key match). Anything
  // else is a stranger's file: --overwrite (or a key mismatch) truncates.
  let start = 0;
  if (opts.overwrite) truncate();
  else {
    const sc = readSidecar();
    if (sc && sc.key === sideKey && fs.existsSync(partialPath)) {
      start = fs.statSync(partialPath).size;
      if (totalSize && start > totalSize) { truncate(); start = 0; }
      // Unknown total size: a resumed 206 cannot be checked for completeness
      // (nothing to compare the final length to), so start over.
      else if (!totalSize) { truncate(); start = 0; }
    } else truncate();
  }
  if (state && state.firstStart === undefined) state.firstStart = start; // where the first attempt really began (after any discard)
  if (totalSize && start === totalSize) return 'ok'; // crashed between rename and receipt: caller verifies
  if (start > 0) { say(`Resuming single-stream at ${(start / 1048576).toFixed(1)} MB`); if (!validators) warnNoValidator(); }
  else writeSidecar();
  let restarts = 0;
  for (;;) {
    if (start === 0) writeSidecar();
    const outcome = await new Promise((resolve, reject) => {
      // Resume is conditional on the file being unchanged: If-Range plus a
      // validator comparison, so a republished file can't silently mix in.
      // If-Range is a single validator (ETag or date), never the object.
      const resumeHeaders = { 'User-Agent': 'agent-dla/1.0', ...(proxyUrl && !isHttps ? {} : headersFor(url)), Range: `bytes=${start}-` };
      if (validators) resumeHeaders['If-Range'] = validators.etag || validators.mtime;
      const reqUrl = requestUrlFor(url, proxyUrl);
      const req = lib.request(reqUrl, {
        method: 'GET',
        headers: start > 0
          ? resumeHeaders
          : { 'User-Agent': 'agent-dla/1.0', ...(proxyUrl && !isHttps ? {} : headersFor(url)) },
        agent: agentFor(proxyUrl, isHttps),
        timeout: TIMEOUT,
        ...TLS_INSECURE,
      }, (res) => {
        let next = null;
        try { next = redirectTarget(res, reqUrl, depth); }
        catch (e) { res.resume(); reject(e); return; }
        if (next) {
          res.resume();
          downloadSingle(next, outPath, proxyUrl, totalSize, depth + 1, sideKey, validators, state).then(() => resolve('ok'), reject);
          return;
        }
        if (start > 0 && res.statusCode === 412) {
          try { res.destroy(); } catch {}
          start = 0; // file changed under us: truncate and take the new version whole
          truncate();
          resolve('restart');
          return;
        }
        if (start > 0 && res.statusCode === 200) {
          try { res.destroy(); } catch {}
          start = 0; // server ignored Range: restart from scratch
          truncate();
          resolve('restart');
          return;
        }
        if (start > 0 && res.statusCode === 206) {
          const cr = parseContentRange(res.headers['content-range']);
          if (!cr || cr.start !== start) {
            try { res.destroy(); } catch {}
            start = 0; // server disagrees about our offset: restart, don't append blindly
            truncate();
            resolve('restart');
            return;
          }
          if (validators) {
            const re = res.headers.etag;
            const rm = res.headers['last-modified'];
            if ((validators.etag && re && re !== validators.etag)
              || (validators.mtime && rm && rm !== validators.mtime)) {
              try { res.destroy(); } catch {}
              start = 0; // republished mid-run: truncate, don't append alien bytes
              truncate();
              resolve('restart');
              return;
            }
          }
        }
        if (res.statusCode !== 200 && res.statusCode !== 206) { res.resume(); reject(httpError(res.statusCode, res.headers)); return; }
        const ws = fs.createWriteStream(partialPath, { flags: start > 0 ? 'a' : 'w' });
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
      const timer = setInterval(() => { if (JSON_MODE) emitProg(); else if (process.stdout.isTTY) draw(); }, JSON_MODE ? 1000 : 250);
      if (JSON_MODE) emitProg();
      res.on('data', (c) => {
        if (DL_FIRED) {
          const err = new Error('deadline exceeded');
          err.fatal = true;
          req.destroy(err);
          try { res.destroy(); } catch {}
          return;
        }
        done += c.length;
        if (MAX_SIZE && done > MAX_SIZE) {
          const err = new Error(`exceeded --max-size ${fmtSize(MAX_SIZE)}`);
          err.fatal = true;
          req.destroy(err);
          try { res.destroy(); } catch {}
        }
      });
      let settled = false;
      const finishOk = () => { if (settled) return; settled = true; clearInterval(timer); if (JSON_MODE) emitProg(); else { draw(); process.stdout.write('\n'); } resolve('ok'); };
      const fail = (e) => { if (settled) return; settled = true; clearInterval(timer); reject(e); };
      pipelineAsync(res, ws).then(finishOk, fail);
    });
    const timeoutErr = new Error('timeout');
    timeoutErr.code = 'TIMEOUT';
    req.on('timeout', () => req.destroy(timeoutErr));
    req.on('error', reject);
    trackReq(req);
    req.end();
    });
    if (outcome === 'ok') return;
    if (++restarts > 1) { const e = new Error('server inconsistent about resume offset'); e.fatal = true; throw e; }
  }
}

// capped fetch (maxBytes) to measure path throughput without downloading the file.
// Only 206 responses with a matching Content-Range count: error pages must
// never rank a proxy as "fast".
function benchFetch(urlStr, proxyUrl, maxBytes = 65536, depth = 0) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const finish = (bytes) => resolve({ bytes, ms: Date.now() - t0 });
    let got = 0, settled = false;
    const done = (bytes) => { if (!settled) { settled = true; finish(bytes); } };
    let u;
    try { u = new URL(urlStr); } catch { done(0); return; }
    const isHttps = u.protocol === 'https:';
    const lib = isHttps ? https : http;
    const benchTimeout = Math.min(TIMEOUT, 10000);
    const reqUrl = requestUrlFor(urlStr, proxyUrl);
    const req = lib.request(reqUrl, {
      // No custom headers through proxies on plain http: the proxy would see
      // credentials in the clear. (https targets are CONNECT-tunneled.)
      method: 'GET',
      headers: { 'User-Agent': 'agent-dla/1.0', ...(proxyUrl && !isHttps ? {} : headersFor(urlStr)), Range: `bytes=0-${maxBytes - 1}` },
      agent: agentFor(proxyUrl, isHttps, benchTimeout),
      timeout: benchTimeout,
      ...TLS_INSECURE,
    }, (res) => {
      let next = null;
      try { next = redirectTarget(res, reqUrl, depth); }
      catch { done(0); res.resume(); return; }
      if (next) {
        res.resume();
        benchFetch(next, proxyUrl, maxBytes, depth + 1).then((r) => done(r.bytes));
        return;
      }
      if (res.statusCode !== 206) { try { res.destroy(); } catch {} done(0); return; }
      const cr = parseContentRange(res.headers['content-range']);
      if (!cr || cr.start !== 0) { try { res.destroy(); } catch {} done(0); return; }
      res.on('data', (c) => {
        got += c.length;
        if (got >= maxBytes) { done(got); req.destroy(); res.destroy(); }
      });
      res.on('end', () => done(got));
      res.on('error', () => done(got > 0 ? got : 0));
    });
    req.on('timeout', () => { req.destroy(); done(got); });
    req.on('error', () => done(got));
    trackReq(req);
    req.end();
  });
}

async function benchAndFilter(url) {
  const intro = `Benchmarking ${PROXIES.length} proxies (64KB each)...`;
  if (JSON_MODE) process.stderr.write(intro); else process.stdout.write(intro);
  const d = await benchFetch(url, null);
  const dKbps = d.bytes / 1024 / Math.max(d.ms / 1000, 0.01);
  const results = [];
  const bqueue = [...PROXIES];
  const enough = () => results.filter((r) => r.kbps >= PROXY_MIN_KBPS).length >= CONNECTIONS;
  await Promise.all(Array.from({ length: Math.min(BENCH_CONC, bqueue.length) }, async () => {
    while (bqueue.length && !enough()) {
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

// post-download verification; bad output (+manifest/sidecar/receipt) is deleted so a rerun starts clean
async function verifyOutput(outPath, manifestPath, expectSize = 0, onBad = null) {
  const bytes = fs.existsSync(outPath) ? fs.statSync(outPath).size : 0;
  const bad = async (msg) => {
    for (const f of [outPath, manifestPath, outPath + '.single.json']) {
      if (!f) continue;
      try { fs.unlinkSync(f); } catch {}
    }
    if (onBad) { try { await onBad(); } catch {} }
    emit({ event: 'error', scope: 'verify', message: msg });
    throw new Error(msg);
  };
  if (EXPECT_SIZE && bytes !== EXPECT_SIZE) await bad(`size mismatch: got ${fmtSize(bytes)}, expected ${fmtSize(EXPECT_SIZE)} (bad output deleted)`);
  if (expectSize > 0 && bytes !== expectSize) await bad(`size mismatch: got ${fmtSize(bytes)}, server said ${fmtSize(expectSize)} (bad output deleted)`);
  let sha = null;
  if (EXPECT_SHA) {
    say('Verifying sha256...');
    sha = await sha256File(outPath);
    if (sha.toLowerCase() !== EXPECT_SHA) await bad(`sha256 mismatch: got ${sha}, expected ${EXPECT_SHA} (bad output deleted)`);
    say('sha256 OK');
  }
  return { bytes, sha: sha || null };
}

// Re-probe the original (unsigned) URL after a signed link expired. Shared
// by the chunked and single-stream paths. A rate-limited probe (403/429 +
// Retry-After, e.g. GitHub's secondary limit) waits once per file, bounded by
// the deadline (finding 5). Throws CHANGED when the file was republished
// (size or validators differ): kept bytes belong to the old version.
async function reprobeSigned(originalTarget, info, state) {
  let fresh;
  try {
    fresh = await getFileInfo(originalTarget);
  } catch (e) {
    const st = e && e.status;
    if ((st === 403 || st === 429) && e.retryAfter > 0 && !state.rateWaited) {
      state.rateWaited = true;
      say(`Refresh rate-limited (HTTP ${st}), waiting ${e.retryAfter}s...`);
      await sleepOrDeadline(Math.min(e.retryAfter, 120) * 1000);
      fresh = await getFileInfo(originalTarget);
    } else throw e;
  }
  if (fresh.size && fresh.size !== info.size) {
    const e = new Error(`file changed mid-download (was ${fmtSize(info.size)}, now ${fmtSize(fresh.size)})`);
    e.fatal = true;
    e.code = 'CHANGED';
    throw e;
  }
  if ((fresh.etag || null) !== (info.etag || null) || (fresh.mtime || null) !== (info.mtime || null)) {
    // Republished under the same size: restart fresh rather than mix versions.
    const e = new Error('file republished mid-download (validator changed)');
    e.fatal = true;
    e.code = 'CHANGED';
    throw e;
  }
  return fresh;
}
// A definitive origin error on the refresh probe (direct 4xx) usually means
// the link was revoked. Callers abort on the second consecutive one.
function isDefinitiveProbeErr(e) {
  return !!(e && e.fatal && e.status >= 400 && e.status < 500 && e.status !== 408 && e.status !== 429);
}
// Refreshes are capped per stretch without progress, not per file: a long
// download over short-lived signed links may refresh many times (R1).
const MAX_REFRESHES_WITHOUT_PROGRESS = 5;

async function runDownload(targetUrl, retryOpts = {}) {
  if (retryOpts.lockBox) return runDownloadInner(targetUrl, retryOpts);
  const lockBox = { release: null };
  try { return await runDownloadInner(targetUrl, { ...retryOpts, lockBox }); }
  finally { if (lockBox.release) lockBox.release(); }
}
async function runDownloadInner(targetUrl, retryOpts = {}) {
  const originalTarget = targetUrl;
  const staleDepth = retryOpts.staleDepth || 0;
  const forceSingle = !!retryOpts.forceSingle;
  const skipUniq = !!retryOpts.isRetry;
  try { HEADER_ORIGIN = new URL(originalTarget).origin; } catch { HEADER_ORIGIN = null; }
  let info = null;
  try { info = await getFileInfo(targetUrl); }
  catch (e) {
    emit({ event: 'error', scope: 'probe', message: e.message });
    throw new Error('Probe failed: ' + e.message);
  }
  const mainStart = Date.now();
  const doneStats = (bytes) => {
    const secs = (Date.now() - mainStart) / 1000;
    return { secs: +secs.toFixed(1), bps: Math.round(bytes / Math.max(secs, 0.01)) };
  };
  const url = info.finalUrl;
  const baseName = opts.output || info.filename || sanitizeUrlName(new URL(url).pathname.split('/').pop() || '') || 'download.bin';
  let outPath = baseName;
  if (opts.dir && !opts.output) {
    fs.mkdirSync(path.resolve(opts.dir), { recursive: true });
    outPath = path.join(path.resolve(opts.dir), path.basename(baseName));
  }
  // Batch collisions: two URLs with the same server-chosen basename must not
  // share an output (the second would read as "cached"). Reruns are unaffected:
  // only paths claimed by THIS process are uniquified.
  if (!skipUniq) {
    let resolved = path.resolve(outPath);
    if (usedOutputs.has(resolved)) {
      const ext = path.extname(outPath);
      const stem = outPath.slice(0, outPath.length - ext.length);
      let k = 1;
      while (usedOutputs.has(path.resolve(`${stem} (${k})${ext}`))) k++;
      outPath = `${stem} (${k})${ext}`;
      resolved = path.resolve(outPath);
    }
    usedOutputs.add(resolved);
  }
  // Completion receipts live in one hidden per-directory store, one file per
  // output (not one shared index): proves THIS tool produced this exact file
  // (key covers origin+path+query+size+validator; only signature/expiry
  // params are dropped from the query, so refreshed presigned URLs hit). Per-file receipts make parallel runs safe: no
  // read-modify-write on a shared file, no shared temp name, and a corrupt
  // receipt can only affect its own output, never siblings.
  const fileKey = manifestKey(originalTarget, info.size, info.etag, info.mtime);
  const receiptDir = path.join(path.dirname(path.resolve(outPath)), '.agent-dla', 'receipts');
  const receiptPath = path.join(receiptDir, path.basename(outPath) + '.json');
  const legacyIndexPath = path.join(path.dirname(path.resolve(outPath)), '.agent-dla-receipts.json');
  const legacySinglePath = outPath + '.receipt.json';
  const readReceipt = () => {
    try {
      const r = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
      if (r && typeof r === 'object') return r;
    } catch (e) {
      if (e && e.code !== 'ENOENT') {
        // Corrupt per-file receipt: confine the damage — drop just this
        // file so its output re-downloads (with -o) or is refused (guard),
        // siblings stay cached.
        try { fs.unlinkSync(receiptPath); } catch {}
      }
      // else: no per-file receipt yet — fall through to legacy upgrade path.
    }
    if (!fs.existsSync(receiptPath)) {
      // Upgrade path: receipts written by older versions (shared index or
      // legacy sidecar). Read-only: never mutate the shared index here, so
      // parallel runs can't clobber each other. A corrupt legacy index is
      // treated as missing, never fatal, never deleted here.
      try {
        const r = JSON.parse(fs.readFileSync(legacySinglePath, 'utf8'));
        if (r && typeof r === 'object') return r;
      } catch {}
      try {
        const idx = JSON.parse(fs.readFileSync(legacyIndexPath, 'utf8'));
        const r = idx && typeof idx === 'object' ? idx[path.basename(outPath)] : null;
        if (r && typeof r === 'object') return r;
      } catch {}
    }
    return null;
  };
  const writeReceipt = (sha) => {
    try {
      fs.mkdirSync(receiptDir, { recursive: true });
      const body = JSON.stringify({
        key: fileKey, url: originalTarget, size: info.size,
        etag: info.etag || null, mtime: info.mtime || null, sha256: sha || null,
      });
      const tmp = `${receiptPath}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, body);
      fs.renameSync(tmp, receiptPath);
    } catch {}
  };
  const dropReceipt = () => {
    try { fs.unlinkSync(receiptPath); } catch {}
    try { fs.unlinkSync(legacySinglePath); } catch {}
    // The legacy shared index is intentionally left untouched: mutating it
    // here would reintroduce the parallel read-modify-write race. It is only
    // ever read (upgrade path) and is superseded by per-file receipts.
  };
  const wipeAll = () => {
    dropReceipt();
    // outPath + '.receipt.json': legacy per-file receipts from older versions.
    for (const f of [outPath, outPath + '.partial', outPath + '.manifest.json', outPath + '.single.json', outPath + '.receipt.json']) {
      try { fs.unlinkSync(f); } catch {}
    }
  };
  // fail fast before spending bandwidth (and before the proxy benchmark)
  const guardFail = (msg) => { emit({ event: 'error', scope: 'guard', message: msg }); throw new Error(msg); };
  try {
    const rel = acquireOutputLock(outPath);
    if (rel && retryOpts.lockBox) retryOpts.lockBox.release = rel;
  } catch (e) { guardFail(e.message); }
  const PROTECTED_NAMES = new Set(['proxies.txt', 'agent-dla.json', 'get-proxies.js', 'agent-dla.js', 'package.json', 'package-lock.json']);
  for (const f of [proxySource, opts.config, opts.list]) {
    if (f) PROTECTED_NAMES.add(path.basename(String(f)).toLowerCase());
  }
  if (!opts.output && /\.(partial|manifest\.json|single\.json|receipt\.json|partial\.lock)$/i.test(path.basename(outPath))) {
    guardFail(`refusing: server filename "${path.basename(outPath)}" looks like a tool staging file (use -o to choose a name)`);
  }
  if (!opts.output && PROTECTED_NAMES.has(path.basename(outPath).toLowerCase())) {
    guardFail(`refusing: server filename "${path.basename(outPath)}" collides with a tool file (use -o to choose a name)`);
  }
  if (info.html && !ALLOW_HTML) guardFail('server returned a web page (text/html), not a file — your link is probably expired or points at a preview/share page (use --allow-html to save it anyway)');
  if (EXPECT_SIZE && info.size && info.size !== EXPECT_SIZE) guardFail(`size mismatch: server says ${fmtSize(info.size)}, expected ${fmtSize(EXPECT_SIZE)}`);
  if (MAX_SIZE && info.size && info.size > MAX_SIZE) guardFail(`refusing: server size ${fmtSize(info.size)} exceeds --max-size ${fmtSize(MAX_SIZE)}`);
  if (EXPECT_TYPE && info.mime && info.mime !== EXPECT_TYPE) guardFail(`type mismatch: server says ${info.mime}, expected ${EXPECT_TYPE}`);
  const outStat = (() => { try { return fs.statSync(outPath); } catch { return null; } })();
  const outComplete = !!(outStat && info.size && outStat.size === info.size);
  if (outComplete) {
    const rc = readReceipt();
    if (rc && rc.key === fileKey) {
      if (EXPECT_SHA) {
        say('Found complete file, verifying sha256...');
        const got = await sha256File(outPath);
        if (got.toLowerCase() !== EXPECT_SHA) {
          say('sha256 mismatch on existing file, redownloading...');
          wipeAll();
        } else {
          emit({ event: 'done', output: path.resolve(outPath), bytes: info.size, seconds: 0, speed_bps: 0, sha256: got, cached: true });
          say(`Already complete -> ${path.resolve(outPath)}`);
          return info.size;
        }
      } else {
        emit({ event: 'done', output: path.resolve(outPath), bytes: info.size, seconds: 0, speed_bps: 0, sha256: rc.sha256 || null, cached: true });
        say(`Already complete -> ${path.resolve(outPath)}`);
        return info.size;
      }
    } else if (EXPECT_SHA) {
      say('Found complete file, verifying sha256...');
      const got = await sha256File(outPath);
      if (got.toLowerCase() !== EXPECT_SHA) {
        say('sha256 mismatch on existing file, redownloading...');
        wipeAll();
      } else {
        writeReceipt(got);
        emit({ event: 'done', output: path.resolve(outPath), bytes: info.size, seconds: 0, speed_bps: 0, sha256: got, cached: true });
        say(`Already complete -> ${path.resolve(outPath)}`);
        return info.size;
      }
    }
    // else: size matches but nothing proves this tool made it — not cached.
    // Fall through to the overwrite rules and a fresh download.
  }

  // Never silently overwrite/clobber with a server-chosen name. Explicit -o
  // is user intent. A .partial/.manifest/.single.json proves a previous run
  // of this tool: resume proceeds. Otherwise a valid receipt is required —
  // a corrupt or missing receipt is refused, never silently overwritten.
  if (!opts.output && !opts.overwrite && fs.existsSync(outPath)
    && !fs.existsSync(outPath + '.partial') && !fs.existsSync(outPath + '.manifest.json') && !fs.existsSync(outPath + '.single.json')) {
    guardFail(`refusing to overwrite existing "${path.basename(outPath)}" with a server-chosen name (use -o or --overwrite)`);
  }
  const SOURCES = [url, ...(opts.mirror || [])];
  await gateProxies(url);
  const infoLine = `Size: ${fmtSize(info.size)} | Range: ${info.range ? 'yes' : 'no'} | Conn: ${CONNECTIONS} | Sources: ${SOURCES.length} | Proxies: ${PROXIES.length}${proxySource ? ` (${proxySource})` : ''}`;
  say(infoLine);
  if (PROXIES.length && !url.startsWith('https:')) {
    warn('plain-http target through proxies: proxies see and can alter content — use --sha256 to be sure of what you got');
  }
  if (PROXIES.length && opts.insecure) {
    warn('-k disables TLS verification, including through proxies (a proxy can intercept TLS) — use --sha256 to be sure of what you got');
  }
  if (PROXIES.length && Object.keys(CUSTOM_HEADERS).length && !url.startsWith('https:')) {
    warn('--header values are withheld from plain-http proxy requests (a proxy would see them); a gated plain-http origin reachable only via proxy may fail — prefer https targets');
  }
  emit({ event: 'start', url: displayUrl(url, true), output: outPath, size: info.size || 0, range: !!info.range, connections: CONNECTIONS, sources: SOURCES.length, proxies: PROXIES.length });
  // Mirror content check: samples from the start AND the end of each mirror
  // must byte-match the primary before the mirror serves chunks. A mirror
  // serving an entirely wrong file is caught; only --sha256 defends against
  // subtler poisoning.
  if (info.range && info.size && SOURCES.length > 1) {
    const sampleAt = async (base, off) => {
      const end = Math.min(off + 1023, info.size - 1);
      for (const via of [null, nextProxy()]) {
        try {
          const r = await requestOnce(base, { Range: `bytes=${off}-${end}` }, via);
          if (r.status === 206 && r.body && r.body.length === end - off + 1) return r.body;
        } catch {}
      }
      return null;
    };
    const first = await sampleAt(url, 0);
    const last = info.size > 2048 ? await sampleAt(url, info.size - 1024) : first;
    if (first) {
      const lastOff = info.size > 2048 ? info.size - 1024 : 0;
      for (const m of SOURCES.slice(1)) {
        let okM = false;
        try {
          const a = await sampleAt(m, 0);
          if (a && a.equals(first)) {
            okM = true;
            if (lastOff > 0 && last) {
              const b = await sampleAt(m, lastOff);
              okM = !!b && b.equals(last);
            }
          }
        } catch { okM = false; }
        if (!okM) {
          warn(`mirror failed content check, evicted: ${displayUrl(m, false)}`);
          SOURCES.splice(SOURCES.indexOf(m), 1);
        }
      }
    }
    if (SOURCES.length > 1 && !EXPECT_SHA) {
      warn('mirrors in use without --sha256: a malicious mirror could alter content undetected');
    }
  }

  if (forceSingle || !info.range || !info.size || CONNECTIONS === 1) {
    if (forceSingle) say('Range stopped working mid-download, falling back to single-stream.');
    say(info.range ? 'Single connection fallback.' : 'Server ignores Range, single-stream download.');
    const singlePartial = outPath + '.partial';
    const singleSidecar = outPath + '.single.json';
    shutdownHandler = (sig) => { emit({ event: 'interrupted', signal: sig, output: outPath }); console.error(`\nInterrupted (${sig}). Partial kept at ${singlePartial} — rerun to resume.`); process.exit(sig === 'SIGTERM' ? 143 : 130); };
    let singleFails = 0;
    // Retry budget: reset only when the .partial grows past its high-water mark
    // by a meaningful amount. A server that ignores Range restarts from 0 on
    // every attempt, so its partial never gets past the mark and retries run out.
    let highWater = null;
    const singleState = {};
    const singleValidators = (info.etag && !/^W\//i.test(info.etag)) ? { etag: info.etag, mtime: null }
      : (info.mtime ? { etag: null, mtime: info.mtime } : null);
    // Signed-link refresh for single-stream (R2): same rules as the chunked
    // path — re-probe the original URL on 401/403/410 from a redirected link,
    // abort on the second consecutive definitive 4xx, and cap only refreshes
    // that deliver no bytes (the .partial size proves progress).
    let singleUrl = url;
    let singleRefreshes = 0;
    let singleRefreshStrikes = 0;
    let partialAtRefresh = -1;
    const singleRefreshState = { rateWaited: false };
    const partialSize = () => { try { return fs.statSync(singlePartial).size; } catch { return 0; } };
    while (true) {
      checkDeadline();
      try {
        await downloadSingle(singleUrl, outPath, nextProxy(), info.size, 0, fileKey, singleValidators, singleState);
        break;
      } catch (e) {
        const cls = classifyErr(e);
        const st = e && e.status;
        if ((st === 401 || st === 403 || st === 410) && singleUrl !== originalTarget) {
          const got = partialSize();
          if (got > partialAtRefresh && partialAtRefresh >= 0) singleRefreshes = 0;
          partialAtRefresh = got;
          if (singleRefreshes >= MAX_REFRESHES_WITHOUT_PROGRESS) {
            const re = new Error('signed link refresh failed repeatedly, aborting');
            emit({ event: 'error', scope: 'single', message: re.message });
            throw re;
          }
          singleRefreshes++;
          let fresh = null;
          try {
            fresh = await reprobeSigned(originalTarget, info, singleRefreshState);
          } catch (re) {
            if (re && re.code === 'CHANGED') {
              // Republished mid-download: kept bytes are the old version.
              try { fs.unlinkSync(singlePartial); } catch {}
              try { fs.unlinkSync(singleSidecar); } catch {}
              if (staleDepth < 2) return runDownload(targetUrl, { forceSingle, staleDepth: staleDepth + 1, isRetry: true, lockBox: retryOpts.lockBox });
              emit({ event: 'error', scope: 'single', message: re.message });
              throw re;
            }
            if (re && re.message === 'deadline exceeded') { emit({ event: 'error', scope: 'single', message: re.message }); throw re; }
            if (isDefinitiveProbeErr(re) && ++singleRefreshStrikes >= 2) {
              emit({ event: 'error', scope: 'single', message: re.message });
              throw new Error(`signed link revoked: ${re.message} (partial kept at ${singlePartial}, rerun to resume)`);
            }
            // first strike or transient probe blip: retry with backoff below
          }
          if (fresh) {
            singleRefreshStrikes = 0;
            emit({ event: 'signed-refresh', from: displayUrl(singleUrl, true), to: displayUrl(fresh.finalUrl, true) });
            say('Signed link expired, refreshed.');
            singleUrl = fresh.finalUrl;
            continue; // resume immediately with the fresh link
          }
        } else if (cls === 'fatal' || e.code === 'ENOTFOUND') { emit({ event: 'error', scope: 'single', message: e.message }); throw e; }
        // Reset only on meaningful progress since the last reset: a server
        // trickling a few bytes per attempt must still exhaust --max-retries.
        const grew = partialSize();
        if (highWater === null) highWater = singleState.firstStart || 0;
        if (grew - highWater >= Math.max(64 * 1024, Math.floor((info.size || 0) / 100))) { singleFails = 0; highWater = grew; }
        singleFails++;
        checkDeadline();
        if (singleFails > MAX_RETRIES) {
          emit({ event: 'error', scope: 'single', message: e.message });
          throw new Error(`single-stream failed ${MAX_RETRIES}x: ${e.message} (partial kept at ${singlePartial}, rerun to resume)`);
        }
        const waitMs = (cls === 'throttle' && e.retryAfter > 0) ? Math.min(e.retryAfter, 120) * 1000 : backoffMs(singleFails);
        emit({ event: 'retry', scope: 'single', fails: singleFails, after_ms: Math.round(waitMs), throttled: cls === 'throttle' });
        say(`Single-stream interrupted (${e.message}), retrying...`);
        await sleepOrDeadline(waitMs);
      }
    }
    const v1 = await verifyOutput(singlePartial, null, info.size, dropReceipt);
    fs.renameSync(singlePartial, outPath);
    try { fs.unlinkSync(singleSidecar); } catch {}
    writeReceipt(v1.sha);
    shutdownHandler = null;
    const st1 = doneStats(v1.bytes);
    emit({ event: 'done', output: path.resolve(outPath), bytes: v1.bytes, seconds: st1.secs, speed_bps: st1.bps, sha256: v1.sha });
    say(`Saved -> ${path.resolve(outPath)}`);
    return v1.bytes;
  }

  const size = info.size;
  const n = Math.min(CONNECTIONS, size);
  const partialPath = outPath + '.partial';
  const manifestPath = outPath + '.manifest.json';
  const pickValidator = () => {
    if (info.etag && !/^W\//i.test(info.etag)) return info.etag; // strong ETags only
    return info.mtime || null;
  };
  let PRIMARY_VALIDATOR = pickValidator();
  RUN_VALIDATORS = (info.etag || info.mtime) ? { etag: info.etag || null, mtime: info.mtime || null } : null;
  const mergeIv = (ivs) => {
    const m = [];
    for (const [a, b] of ivs.slice().sort((x, y) => x[0] - y[0])) {
      const l = m[m.length - 1];
      if (l && a <= l[1] + 1) l[1] = Math.max(l[1], b);
      else m.push([a, b]);
    }
    return m;
  };
  const validIv = (a) => Array.isArray(a) && Number.isInteger(a[0]) && Number.isInteger(a[1]) && a[0] >= 0 && a[1] >= a[0] && a[1] < size;
  let doneIv = [];
  const partialStat = (() => { try { return fs.statSync(partialPath); } catch { return null; } })();
  try {
    const m = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    if (m && m.key === fileKey && Array.isArray(m.done) && m.done.every(validIv)
      && partialStat && partialStat.size === size) {
      doneIv = mergeIv([...m.done, ...Object.values(m.active || {}).filter((a) => Array.isArray(a) && a[1] > a[0]).map(([s, c]) => [s, c - 1]).filter(validIv)]);
      say(`Resuming from manifest (${doneIv.reduce((t, [s, e]) => t + (e - s + 1), 0)} of ${size} bytes kept).`);
      if (!info.etag && !info.mtime) warnNoValidator();
    } else {
      try { fs.unlinkSync(partialPath); } catch {}
      try { fs.unlinkSync(manifestPath); } catch {}
    }
  } catch {
    try { fs.unlinkSync(partialPath); } catch {}
    try { fs.unlinkSync(manifestPath); } catch {}
  }
  const outFd = fs.openSync(partialPath, fs.existsSync(partialPath) ? 'r+' : 'w+');
  try { fs.ftruncateSync(outFd, size); } catch {}
  const snapshotActive = () => {
    const o = {};
    for (const [, rec] of inflight) o[rec.job.i] = [rec.job.start, rec.job.start + (active.get(rec.job.i) || 0)];
    return o;
  };
  const writeManifest = (snap) => {
    try {
      const body = JSON.stringify({
        key: fileKey, url: originalTarget, size, etag: info.etag || null, mtime: info.mtime || null,
        done: doneIv, active: snap || snapshotActive(),
      });
      fs.writeFileSync(manifestPath + '.tmp', body);
      fs.renameSync(manifestPath + '.tmp', manifestPath);
    } catch {}
  };
  const recordDone = (s, e) => {
    if (e >= s) { doneIv.push([s, e]); doneIv = mergeIv(doneIv); }
  };
  const gapsOf = () => {
    const gaps = [];
    let cur = 0;
    for (const [s, e] of doneIv) {
      if (s > cur) gaps.push([cur, s - 1]);
      cur = Math.max(cur, e + 1);
    }
    if (cur < size) gaps.push([cur, size - 1]);
    return gaps;
  };
  const jobs = [];
  {
    const gaps = gapsOf();
    const gapBytes = gaps.reduce((t, [s, e]) => t + (e - s + 1), 0);
    const target = Math.max(1, Math.ceil(gapBytes / Math.max(n, 1)));
    let cur = null;
    const pushJob = (s, e) => jobs.push({ i: jobs.length, start: s, end: e, src: SOURCES[jobs.length % SOURCES.length] });
    for (const [s, e] of gaps) {
      let p = s;
      while (p <= e) {
        if (!cur) cur = { start: p, len: 0 };
        const take = Math.min(target - cur.len, e - p + 1);
        cur.len += take;
        p += take;
        if (cur.len >= target) { pushJob(cur.start, p - 1); cur = null; }
      }
      // A job never spans a gap boundary: it would re-download bytes the
      // manifest already holds (and `len` would understate its true extent).
      if (cur) { pushJob(cur.start, cur.start + cur.len - 1); cur = null; }
    }
  }

  let doneBytes = doneIv.reduce((t, [s, e]) => t + (e - s + 1), 0);
  const t0 = Date.now();
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
  const timer = setInterval(() => { if (process.stdout.isTTY) draw(); else if (JSON_MODE) draw(); }, 250);

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
      const cursor = job.start + got; // bytes [start, cursor) are already on disk
      const remain = job.end - cursor + 1;
      if (speed >= floor || remain < SPLIT_MIN_REMAIN) continue;
      if (cursor > job.start) { recordDone(job.start, cursor - 1); writeManifest(); }
      const mid = cursor + Math.floor((remain - 1) / 2);
      const half = { i: jobs.length, start: mid + 1, end: job.end, src: SOURCES[jobs.length % SOURCES.length], splits: 0 };
      job.start = cursor;
      job.end = mid;
      job.splits = (job.splits || 0) + 1;
      job.lastSplit = Date.now();
      jobs.push(half);
      queue.push(half);
      pending++;
      splitCount++;
      active.set(job.i, 0);
      active.set(half.i, 0);
      try { if (token && token.req) { const e = new Error('split straggler'); e.code = 'SPLIT'; token.req.destroy(e); } } catch {}
      emit({ event: 'split', chunk: job.i, new_chunk: half.i, at: mid, speed_bps: Math.round(speed) });
      say(`Splitting stalled chunk ${job.i} at ${fmtSize(mid - job.start + 1)} (was ${fmtSize(remain)} @ ${(speed / 1024).toFixed(0)} KB/s)`);
    }
  }
  const splitTimer = setInterval(splitStragglers, 2000);
  const manifestTimer = setInterval(() => writeManifest(), 1000); // hard kills keep ≤1s of progress

  // Path-scoped failures: a 4xx (or any error) from a proxy or mirror evicts
  // that path for the run; only the direct primary can fail the whole file.
  const badMirrors = new Set();
  const badProxies = new Set();
  const mirrorStrikes = new Map();
  let primaryUrl = url;
  let signedRefreshes = 0; // refreshes since the download last made progress
  let bytesSinceRefresh = 0;
  let refreshingSigned = null;
  let refreshDefinitiveFails = 0; // consecutive definitive 4xx on the refresh probe
  const refreshState = { rateWaited: false }; // one Retry-After wait per file (finding 5)
  function pickSrc(job) {
    if (job.src && !badMirrors.has(job.src)) return job.src;
    for (const s of SOURCES) { if (!badMirrors.has(s) && s !== primaryUrl) return s; }
    return primaryUrl;
  }
  function pickProxy() {
    if (!PROXIES.length) return null;
    for (let k = 0; k < PROXIES.length; k++) {
      const p = nextProxy();
      if (!badProxies.has(p)) return p;
    }
    return null; // everything evicted: go direct
  }
  function isDirectPath(src, proxy) { return !proxy && src === primaryUrl; }
  async function refreshSignedUrl(job) {
    // 401/403/410 from a redirected primary: the signed link likely expired.
    // Bytes received since the last refresh prove the refreshed link worked:
    // only refreshes that deliver nothing count toward the cap (R1).
    if (!refreshingSigned) {
      if (bytesSinceRefresh > 0) signedRefreshes = 0;
      bytesSinceRefresh = 0;
    }
    // A refresh already in flight is joined before the cap is consulted: the
    // cap decides whether to START another one, not whether to wait for one.
    if (refreshingSigned) { await refreshingSigned.catch(() => {}); return job.src === primaryUrl; }
    if (signedRefreshes >= MAX_REFRESHES_WITHOUT_PROGRESS) {
      const e = new Error('signed link refresh failed repeatedly, aborting');
      e.fatal = true;
      throw e;
    }
    refreshingSigned = (async () => {
      signedRefreshes++;
      const fresh = await reprobeSigned(originalTarget, info, refreshState);
      const freshValidator = (fresh.etag && !/^W\//i.test(fresh.etag)) ? fresh.etag : (fresh.mtime || null);
      const old = primaryUrl;
      primaryUrl = fresh.finalUrl;
      PRIMARY_VALIDATOR = freshValidator;
      for (const j of jobs) { if (j.src === old) j.src = primaryUrl; }
      emit({ event: 'signed-refresh', from: displayUrl(old, true), to: displayUrl(primaryUrl, true) });
      say('Signed link expired, refreshed.');
    })();
    try { await refreshingSigned; }
    catch (e) {
      refreshingSigned = null;
      if (e && e.code === 'CHANGED') throw e;
      if (e && e.message === 'deadline exceeded') throw e;
      // A definitive origin error (direct 4xx) usually means the link is
      // revoked: abort — but only on the SECOND consecutive one, so a
      // one-off 403 (flap) gets one more chance (finding 5). Anything else
      // (DNS, reset, 5xx, timeout) returns false: retry later on another path.
      if (isDefinitiveProbeErr(e)) {
        if (++refreshDefinitiveFails >= 2) throw e;
        return false; // first strike: requeue, confirm on the next 403
      }
      return false; // transient probe blip: retry later on another path
    }
    refreshingSigned = null;
    refreshDefinitiveFails = 0; // a good refresh clears the strike count
    if (job.src !== primaryUrl) job.src = primaryUrl;
    return true;
  }
  // returns true on success, false to requeue, { fatal } to abort everything
  async function runJob(job) {
    const ATTEMPTS = MAX_RETRIES === 0 ? 1 : Math.min(Math.max(RETRIES + 1, PROXIES.length || 0), 16);
    // Only bytes fetched with the current primary link prove a refresh
    // worked; in-flight connections on older links don't (R1).
    let attemptUrl = null;
    const track = (d) => { if (attemptUrl === primaryUrl) bytesSinceRefresh += d; active.set(job.i, (active.get(job.i) || 0) + d); };
    const finishAttempt = (okBytes) => {
      inflight.delete(job.i);
      active.delete(job.i);
      if (okBytes) {
        doneBytes += okBytes;
        recordDone(job.start, job.end);
        writeManifest();
        emit({ event: 'chunk-done', chunk: job.i, bytes: okBytes, resumed: false, via: job.lastVia || 'direct' });
      }
    };
    let justRefreshed = false;
    for (let a = 0; a < ATTEMPTS; a++) {
      // Don't hammer back-to-back, except right after a refresh: the fresh
      // link may be short-lived, so use it at once.
      if (a > 0 && !justRefreshed) await sleep(300);
      justRefreshed = false;
      try { checkDeadline(); } catch (e) { return { fatal: e }; }
      const proxy = pickProxy();
      const src = pickSrc(job);
      job.src = src;
      const token = {};
      active.set(job.i, 0);
      inflight.set(job.i, { job, t0: Date.now(), token });
      try {
        job.lastVia = redactProxy(proxy);
        attemptUrl = src;
        const got = await downloadRange(src, job.start, job.end, outFd, proxy, track, token, 0, size, src === primaryUrl ? PRIMARY_VALIDATOR : null, src === primaryUrl ? RUN_VALIDATORS : null);
        finishAttempt(got);
        return true;
      } catch (e) {
        inflight.delete(job.i);
        const got = active.get(job.i) || 0;
        active.delete(job.i);
        // Dropped connections keep their bytes: positions [start, start+got)
        // were streamed in order, so record them and resume after them.
        // Validation failures prove nothing: retry those ranges whole.
        if (got > 0 && !e.rangeInvalid && job.start + got <= job.end) {
          recordDone(job.start, job.start + got - 1);
          job.start += got;
          writeManifest();
        }
        const cls = classifyErr(e);
        if (cls === 'split') return 'split';
        if (e.code === 'CHANGED') return { fresh: true }; // version changed: wipe and restart
        if (e.message === 'deadline exceeded') return { fatal: e };
        const direct = isDirectPath(src, proxy);
        const status = e && e.status;
        const path4xx = status >= 400 && status < 500 && status !== 408 && status !== 429;
        if (!direct) {
          // Blame precisely: a proxy in use condemns only the proxy (the
          // mirror may be fine); a mirror is evicted on 4xx/validation, and
          // only after repeated transient strikes.
          if (proxy) badProxies.add(proxy);
          if (src !== primaryUrl && (path4xx || cls === 'fatal' || e.rangeInvalid)) badMirrors.add(src);
          else if (src !== primaryUrl && !proxy) {
            const strikes = (mirrorStrikes.get(src) || 0) + 1;
            mirrorStrikes.set(src, strikes);
            if (strikes >= 2) badMirrors.add(src);
          }
          if ((status === 401 || status === 403 || status === 410) && src === primaryUrl && primaryUrl !== originalTarget) {
            try {
              if (await refreshSignedUrl(job)) { justRefreshed = true; continue; }
            } catch (re) {
              if (re && re.code === 'CHANGED') return { fresh: true };
              return { fatal: re }; // definitive (revoked/cap): abort, don't requeue
            }
          }
          if (path4xx || cls === 'fatal' || e.code === 'ENOTFOUND') continue; // next path, no backoff
          if (cls === 'throttle' && e.retryAfter > 0) {
            say(`Chunk ${job.i} throttled (HTTP ${e.status}), waiting ${e.retryAfter}s...`);
            try { await sleepOrDeadline(Math.min(e.retryAfter, 120) * 1000); }
            catch (de) { return { fatal: de }; }
          }
          continue;
        }
        if (e.code === 'ENOTFOUND') return { fatal: e };
        if (e.code === 'CHANGED') return { fresh: true }; // version changed: wipe and restart
        if (e.message === 'deadline exceeded') return { fatal: e };
        if (e.code === 'STALE_RANGE') return { stale: true }; // range ignored: single-stream fallback
        if ((status === 401 || status === 403 || status === 410) && primaryUrl !== originalTarget) {
          try {
            if (await refreshSignedUrl(job)) { justRefreshed = true; continue; } // retry now with the fresh link, no backoff
          } catch (re) {
            if (re && re.code === 'CHANGED') return { fresh: true };
            return { fatal: re }; // definitive (revoked/cap): abort, don't requeue
          }
          // Refresh returned false (transient blip): requeue with backoff
          // rather than aborting. Bounded by MAX_RETRIES and the deadline.
          return false;
        }
        if (cls === 'fatal' || path4xx) return { fatal: e };
        if (cls === 'throttle' && e.retryAfter > 0) {
          say(`Chunk ${job.i} throttled (HTTP ${e.status}), waiting ${e.retryAfter}s...`);
          try { await sleepOrDeadline(Math.min(e.retryAfter, 120) * 1000); }
          catch (de) { return { fatal: de }; }
        }
      }
    }
    // last resort each round: direct connection
    const token = {};
    active.set(job.i, 0);
    inflight.set(job.i, { job, t0: Date.now(), token });
    try {
      job.lastVia = 'direct';
      attemptUrl = primaryUrl;
      const got = await downloadRange(primaryUrl, job.start, job.end, outFd, null, track, token, 0, size, PRIMARY_VALIDATOR, RUN_VALIDATORS);
      finishAttempt(got);
      return true;
    } catch (e) {
      inflight.delete(job.i);
      const got = active.get(job.i) || 0;
      active.delete(job.i);
      if (got > 0 && !e.rangeInvalid && job.start + got <= job.end) {
        recordDone(job.start, job.start + got - 1);
        job.start += got;
        writeManifest();
      }
      const cls = classifyErr(e);
      if (cls === 'split') return 'split';
      if (e.code === 'CHANGED') return { fresh: true }; // version changed: wipe and restart
      if (e.message === 'deadline exceeded') return { fatal: e };
      if (cls === 'fatal' || e.code === 'ENOTFOUND') {
        const status = e && e.status;
        if ((status === 401 || status === 403 || status === 410) && primaryUrl !== originalTarget) {
          try {
            if (await refreshSignedUrl(job)) return 'refreshed'; // requeue now: a backoff could outlive the fresh link
          } catch (re) {
            if (re && re.code === 'CHANGED') return { fresh: true };
            return { fatal: re }; // definitive (revoked/cap): abort, don't requeue
          }
          // Refresh returned false (transient blip): requeue with backoff
          // rather than aborting. Bounded by MAX_RETRIES and the deadline.
          return false;
        }
        return { fatal: e };
      }
      return false;
    }
  }

  // limit simultaneous sockets to n but avoid EMFILE: cap at 32 concurrent file writes is fine on win
  const CONC = Math.min(n, 32);
  const queue = [...jobs];
  pending = jobs.length;
  splitBudget = jobs.length * 2;
  let fatal = null;
  let staleRestart = false;
  let freshRestart = false;
  let down = false;
  shutdownHandler = async (sig) => {
    if (down) return;
    down = true;
    clearInterval(timer);
    clearInterval(splitTimer);
    clearInterval(manifestTimer);
    for (const [, f] of inflight) { try { if (f.token && f.token.req) f.token.req.destroy(); } catch {} }
    await sleep(500); // let in-flight catches settle
    writeManifest();
    try { fs.closeSync(outFd); } catch {}
    emit({ event: 'interrupted', signal: sig, chunks_done: jobs.length - pending, chunks_total: jobs.length, partial: partialPath });
    console.error(`\nInterrupted (${sig}). ${jobs.length - pending}/${jobs.length} chunks done, progress kept in ${partialPath} + manifest — rerun the same command to resume.`);
    process.exit(sig === 'SIGTERM' ? 143 : 130);
  };
  const workers = Array.from({ length: CONC }, async () => {
    while (true) {
      const j = queue.shift();
      if (!j) { if (pending === 0 || fatal || staleRestart || freshRestart || down) return; await sleep(500); continue; }
      const r = await runJob(j);
      if (down) return;
      if (r === true) { pending--; continue; }
      if (r === 'split') { queue.push(j); continue; } // first half still pending, requeue it
      if (r === 'refreshed') { queue.push(j); continue; } // fresh signed link: retry now (refresh cap bounds this)
      if (r && r.stale) {
        staleRestart = true;
        pending = 0;
        queue.length = 0;
        return;
      }
      if (r && r.fresh) {
        freshRestart = true;
        pending = 0;
        queue.length = 0;
        return;
      }
      if (r && r.fatal) {
        fatal = new Error(`chunk ${j.i} unrecoverable: ${r.fatal.message} (progress kept in ${partialPath} + manifest, rerun resumes what completed)`);
        pending = 0;
        queue.length = 0;
        return;
      }
      j.fails = (j.fails || 0) + 1;
      totalRetries++;
      try { checkDeadline(); } catch (e) {
        fatal = e;
        pending = 0;
        queue.length = 0;
        return;
      }
      emit({ event: 'retry', scope: 'chunk', chunk: j.i, fails: j.fails, after_ms: Math.round(backoffMs(j.fails)) });
      if (j.fails > MAX_RETRIES) {
        fatal = new Error(`chunk ${j.i} failed ${MAX_RETRIES}x (progress kept in ${partialPath} + manifest, rerun to resume)`);
        pending = 0;
        queue.length = 0;
        return;
      }
      try { await backoff(j.fails); }
      catch (e) {
        fatal = e;
        pending = 0;
        queue.length = 0;
        return;
      }
      if (fatal || staleRestart || freshRestart || down) return;
      queue.push(j);
    }
  });
  await Promise.all(workers);
  clearInterval(timer);
  clearInterval(splitTimer);
  clearInterval(manifestTimer);
  try { fs.closeSync(outFd); } catch {}
  if (fatal) throw fatal;
  if (freshRestart) {
    // The file was republished mid-download: kept bytes belong to the old
    // version. Wipe everything and redo the file with a fresh probe.
    // A repeat means validators flap (e.g. load-balanced backends with
    // identical bytes): single-stream tolerates that, chunked validation
    // does not.
    try { fs.unlinkSync(partialPath); } catch {}
    try { fs.unlinkSync(manifestPath); } catch {}
    if (staleDepth < 1) return runDownload(targetUrl, { staleDepth: staleDepth + 1, isRetry: true, lockBox: retryOpts.lockBox });
    say('Validators kept changing, falling back to single-stream.');
    return runDownload(targetUrl, { forceSingle: true, staleDepth: staleDepth + 1, isRetry: true, lockBox: retryOpts.lockBox });
  }
  if (staleRestart) {
    // The server stopped honoring Range mid-run: wipe the chunked state and
    // redo this file as a single stream (which tolerates 200s).
    try { fs.unlinkSync(partialPath); } catch {}
    try { fs.unlinkSync(manifestPath); } catch {}
    if (staleDepth < 2) return runDownload(targetUrl, { forceSingle: true, staleDepth: staleDepth + 1, isRetry: true, lockBox: retryOpts.lockBox });
    throw new Error('server repeatedly ignored Range requests');
  }
  if (JSON_MODE) {
    const elFin = (Date.now() - t0) / 1000;
    emit({
      event: 'progress', bytes_done: size, total: size,
      speed_bps: Math.round(size / Math.max(elFin, 0.01)), eta_s: 0,
      chunks_done: jobs.length, chunks_total: jobs.length, active: 0, retries: totalRetries, splits: splitCount,
    });
  }
  say('Verifying...');
  const v = await verifyOutput(partialPath, manifestPath, size, dropReceipt);
  fs.renameSync(partialPath, outPath);
  try { fs.unlinkSync(manifestPath); } catch {}
  writeReceipt(v.sha);
  shutdownHandler = null;
  try { fs.closeSync(outFd); } catch {}
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
  emit({ event: 'batch', files: targets.length, schema: 1 });
  const bt0 = Date.now();
  let bytes = 0;
  const failed = [];
  for (const t of targets) {
    DL_AT = DEADLINE_MS > 0 ? Date.now() + DEADLINE_MS : 0;
    DL_FIRED = false;
    if (dlTimer) { clearTimeout(dlTimer); dlTimer = null; }
    if (DEADLINE_MS > 0) {
      dlTimer = setTimeout(() => {
        DL_FIRED = true;
        for (const r of DL_REQS) { try { r.destroy(deadlineErr()); } catch {} }
      }, DEADLINE_MS);
    }
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
    if (dlTimer) { clearTimeout(dlTimer); dlTimer = null; }
    DL_FIRED = false;
  }
  const bsecs = (Date.now() - bt0) / 1000;
  emit({ event: 'batch-done', files: targets.length, completed: targets.length - failed.length, failed, bytes, seconds: +bsecs.toFixed(1), schema: 1 });
  if (failed.length) { console.error(`${failed.length}/${targets.length} failed`); process.exit(1); }
})().catch(e => { emit({ event: 'error', message: e.message }); console.error(e.message); process.exit(1); });
