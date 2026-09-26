// Shared helpers for the agent-dla test suite.
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');

const AGENT_DLA = path.resolve(__dirname, '..', 'agent-dla.js');
const BASE = path.join(os.tmpdir(), 'agent-dla-tests');

function workdir(name) {
  const dir = path.join(BASE, name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function makeFile(dir, name, size, mult = 7) {
  const buf = Buffer.allocUnsafe(size);
  for (let i = 0; i < size; i++) buf[i] = (i * mult) & 0xff;
  fs.writeFileSync(path.join(dir, name), buf);
  return { path: path.join(dir, name), hash: crypto.createHash('sha256').update(buf).digest('hex'), size };
}

function sha256(p) {
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Origin server. files: { '/a.bin': { buf } }. hooks(req, { start, end, size, key, count }) may
// return 'kill' (destroy socket), { status, headers, body } (override), or { slowBps } (throttle).
function startServer(files, hooks) {
  const hits = new Map();
  const fds = {};
  for (const [p, f] of Object.entries(files)) {
    fs.writeFileSync(f.tmp, f.buf);
    fds[p] = fs.openSync(f.tmp, 'r');
  }
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const f = files[u.pathname];
    if (!f) { res.writeHead(404); res.end('nope'); return; }
    const size = f.buf.length;
    const m = /bytes=(\d+)-(\d*)/.exec(req.headers.range || '');
    const start = m ? parseInt(m[1], 10) : 0;
    const end = m && m[2] ? parseInt(m[2], 10) : size - 1;
    const key = `${u.pathname}:${start}-${end}`;
    const count = (hits.get(key) || 0) + 1;
    hits.set(key, count);
    const hook = hooks ? hooks(req, { start, end, size, key, count, path: u.pathname }) : null;
    if (hook === 'kill') { req.socket.destroy(); return; }
    if (hook && hook.status) {
      res.writeHead(hook.status, hook.headers || {});
      res.end(hook.body || '');
      return;
    }
    const slowBps = (hook && hook.slowBps) || 0;
    const h = { 'Accept-Ranges': 'bytes', 'Content-Length': end - start + 1 };
    if (f.type) h['Content-Type'] = f.type;
    if (f.disposition) h['Content-Disposition'] = f.disposition;
    if (m) h['Content-Range'] = `bytes ${start}-${end}/${size}`;
    res.writeHead(m ? 206 : 200, h);
    const fd = fds[u.pathname];
    (async () => {
      const b = Buffer.allocUnsafe(16384);
      for (let off = start; off <= end; off += 16384) {
        if (res.destroyed) return;
        const len = Math.min(16384, end - off + 1);
        fs.readSync(fd, b, 0, len, off);
        res.write(b.subarray(0, len));
        if (slowBps) await sleep((len / slowBps) * 1000);
      }
      res.end();
    })().catch(() => { try { res.destroy(); } catch {} });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({
      server,
      port: server.address().port,
      url: (p) => `http://127.0.0.1:${server.address().port}${p}`,
      close: () => new Promise((r) => {
        server.close(() => { for (const fd of Object.values(fds)) { try { fs.closeSync(fd); } catch {} } r(); });
      }),
    }));
  });
}

function runAccel(args, { cwd, env, timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn('node', [AGENT_DLA, ...args], { cwd, env: { ...process.env, ...env } });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    let timedOut = false;
    const kill = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
    child.on('close', (code) => { clearTimeout(kill); resolve({ code, stdout, stderr, timedOut }); });
    child.on('error', (e) => { clearTimeout(kill); resolve({ code: -1, stdout, stderr: stderr + e.message, timedOut }); });
  });
}

function events(stdout) {
  return stdout.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
}

module.exports = { AGENT_DLA, workdir, makeFile, sha256, sleep, startServer, runAccel, events };
