const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const H = require('./helpers');

describe('corruption', () => {
  it('test server round-trips random data exactly', { timeout: 60000 }, async () => {
    const work = H.workdir('corr-server');
    const buf = crypto.randomBytes(4 * 1024 * 1024);
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } });
    try {
      const got = await new Promise((ok, rej) => {
        http.get(srv.url('/f.bin'), (res) => {
          const c = [];
          res.on('data', (d) => c.push(d));
          res.on('end', () => ok(Buffer.concat(c)));
          res.on('error', rej);
        }).on('error', rej);
      });
      assert.ok(got.equals(buf), 'server must serve bytes exactly');
    } finally {
      await srv.close();
    }
  });

  it('Range-ignoring mirror never yields a wrong file with exit 0', { timeout: 120000 }, async () => {
    const work = H.workdir('corr-mirror');
    const src = H.makeFile(work, 'src.bin', 4 * 1024 * 1024);
    const buf = fs.readFileSync(src.path);
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } });
    const mirror = http.createServer((q, s) => { s.writeHead(200, { 'Content-Length': buf.length }); s.end(buf); });
    await new Promise((ok) => mirror.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '--mirror', `http://127.0.0.1:${mirror.address().port}/f.bin`, '-o', out, '-n', '4', '--json'], { cwd: work });
      if (r.code === 0) assert.equal(H.sha256(out), src.hash, 'exit 0 requires byte-identical output');
      else assert.ok(/ignored Range|Content-Range|unrecoverable/.test(r.stdout + r.stderr));
    } finally {
      mirror.close();
      await srv.close();
    }
  });

  it('Range-ignoring proxy is evicted, download completes direct', { timeout: 120000 }, async () => {
    const work = H.workdir('corr-proxy');
    const src = H.makeFile(work, 'src.bin', 2 * 1024 * 1024);
    const buf = fs.readFileSync(src.path);
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } });
    // proxy that answers every Range request with the full body (200)
    const px = await H.startForwardProxy((clientReq, clientRes) => {
      let target;
      try { target = new URL(clientReq.url); } catch { clientRes.writeHead(400); clientRes.end(); return; }
      const preq = http.request({ host: target.hostname, port: target.port || 80, path: '/f.bin', method: 'GET' }, (pres) => {
        const c = [];
        pres.on('data', (d) => c.push(d));
        pres.on('end', () => {
          const body = Buffer.concat(c);
          clientRes.writeHead(200, { 'Content-Length': body.length });
          clientRes.end(body);
        });
      });
      preq.on('error', () => { try { clientRes.writeHead(502); clientRes.end(); } catch {} });
      preq.end();
    });
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), `http://127.0.0.1:${px.port}\n`);
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2', '--json', '--no-auto-refresh'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      px.close();
      await srv.close();
    }
  });

  it('stale split ranges from a previous run are never reused', { timeout: 180000 }, async () => {
    const work = H.workdir('corr-split');
    const MB = 1048576;
    const buf = crypto.randomBytes(16 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let run = 1;
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } }, (req, { start, end }) => {
      if (run === 1) {
        if (start === 8 * MB && end === 12 * MB - 1) return { slowBps: 50 * 1024 };
        if (start === 8 * MB && end === 10 * MB - 1) return { status: 500 };
        if (start === 4 * MB) return { status: 500 };
      } else if (start === 4 * MB && end === 8 * MB - 1) return { slowBps: 50 * 1024 };
      return null;
    });
    const FAST = { AGENT_DLA_SPLIT_STALL_S: '5', AGENT_DLA_SPLIT_COOLDOWN_S: '5' };
    try {
      const out = path.join(work, 'out.bin');
      const c = spawn('node', [H.AGENT_DLA, srv.url('/f.bin'), '-o', out, '-n', '4'], { cwd: work, env: { ...process.env, ...FAST } });
      const closed = new Promise((r) => c.on('close', r));
      await H.sleep(14000); // stalled chunks guarantee mid-flight
      c.kill();
      await closed;
      run = 2;
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work, env: FAST });
      assert.equal(r.code, 0);
      const outBuf = fs.readFileSync(out);
      assert.equal(crypto.createHash('sha256').update(outBuf).digest('hex'), hash);
      assert.ok(outBuf.subarray(6 * MB, 8 * MB).equals(buf.subarray(6 * MB, 8 * MB)),
        'bytes 6-8MB must be source bytes 6-8MB, not a stale split range');
    } finally {
      await srv.close();
    }
  });

  it('weak ETag servers and foreign-ETag mirrors serve 206s', { timeout: 120000 }, async () => {
    const work = H.workdir('corr-weaketag');
    const buf = crypto.randomBytes(4 * 1024 * 1024);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let mirrorSawIfRange = 0;
    let mirrorReqs = 0;
    function strictServe(etag) {
      return (q, res) => {
        if (q.headers['if-range']) {
          // RFC-strict: weak or mismatched If-Range is ignored -> full 200
          res.writeHead(200, { 'Content-Length': buf.length, ETag: etag });
          res.end(buf);
          return;
        }
        const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
        if (m) {
          const a = +m[1], b = +m[2];
          res.writeHead(206, { 'Content-Length': b - a + 1, 'Content-Range': `bytes ${a}-${b}/${buf.length}`, ETag: etag });
          res.end(buf.subarray(a, b + 1));
          return;
        }
        res.writeHead(200, { 'Content-Length': buf.length, ETag: etag });
        res.end(buf);
      };
    }
    const p = http.createServer(strictServe('W/"primary-v1"'));
    await new Promise((ok) => p.listen(0, '127.0.0.1', ok));
    const m = http.createServer((q, res) => {
      mirrorReqs++;
      if (q.headers['if-range']) mirrorSawIfRange++;
      strictServe('"mirror-v9"')(q, res);
    });
    await new Promise((ok) => m.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([
        `http://127.0.0.1:${p.address().port}/f.bin`,
        '--mirror', `http://127.0.0.1:${m.address().port}/f.bin`,
        '-o', out, '-n', '4', '--json',
      ], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), hash);
      assert.equal(mirrorSawIfRange, 0, 'primary validator must never go to a mirror');
      assert.ok(mirrorReqs > 0, 'mirror actually served chunks');
      assert.ok(H.events(r.stdout).filter((e) => e.event === 'chunk-done').length >= 4, 'stayed in chunked mode (no single-stream fallback)');
    } finally {
      p.close();
      m.close();
    }
  });

  it('manifest without its partial is discarded, download restarts', { timeout: 180000 }, async () => {
    const work = H.workdir('corr-manifest-gone');
    const src = H.makeFile(work, 'src.bin', 40 * 1024 * 1024);
    const srv = await H.startServer(
      { '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } },
      () => ({ slowBps: 2 * 1024 * 1024 }),
    );
    try {
      const out = path.join(work, 'o.bin');
      const c = spawn('node', [H.AGENT_DLA, srv.url('/f.bin'), '-o', out, '-n', '4'], { cwd: work });
      const closed = new Promise((r) => c.on('close', r));
      await H.sleep(4000); // 10MB chunks at ~2MB/s: definitely mid-flight
      c.kill();
      await closed;
      assert.ok(fs.existsSync(out + '.manifest.json'), 'manifest exists after kill');
      fs.unlinkSync(out + '.partial'); // cleaner/antivirus/user removed it
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash, 'fresh download, no zero holes');
    } finally {
      await srv.close();
    }
  });

  it('zero-byte file downloads as empty with exit 0', { timeout: 60000 }, async () => {    const work = H.workdir('corr-zero');
    const s = http.createServer((q, res) => {
      if (q.headers.range) { res.writeHead(416, { 'Content-Range': 'bytes */0' }); res.end(); }
      else { res.writeHead(200, { 'Content-Length': 0 }); res.end(); }
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'empty.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/empty.txt`, '-o', out, '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(fs.statSync(out).size, 0);
    } finally {
      s.close();
    }
  });
});
