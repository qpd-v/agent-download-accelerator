const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { spawn } = require('child_process');
const crypto = require('crypto');
const H = require('./helpers');

const MB = 1048576;

describe('reliability', () => {
  it('403 proxy is dropped at benchmark, download completes direct', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-403proxy');
    const src = H.makeFile(work, 'src.bin', 4 * MB);
    const buf = fs.readFileSync(src.path);
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } });
    const p = http.createServer((q, s) => { s.writeHead(403, { 'Content-Type': 'text/html' }); s.end(Buffer.alloc(300000, 65)); });
    await new Promise((ok) => p.listen(0, '127.0.0.1', ok));
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), `http://127.0.0.1:${p.address().port}\n`);
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '4', '--json', '--no-auto-refresh'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      p.close();
      await srv.close();
    }
  });

  it('404 mirror is evicted, download completes from primary', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-404mirror');
    const src = H.makeFile(work, 'src.bin', 4 * MB);
    const buf = fs.readFileSync(src.path);
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } });
    try {
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '--mirror', srv.url('/missing.bin'), '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('expired signed redirect is refreshed, download completes', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-signed');
    const crypto = require('crypto');
    const buf = crypto.randomBytes(8 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let dropped = false;
    const s = http.createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      if (u.pathname === '/release') { res.writeHead(302, { Location: `/signed?exp=${Date.now() + 3000}` }); res.end(); return; }
      if (Date.now() > +u.searchParams.get('exp')) { res.writeHead(403); res.end('<Error>expired</Error>'); return; }
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = +m[1], b = +m[2];
      res.writeHead(206, { 'Content-Length': b - a + 1, 'Content-Range': `bytes ${a}-${b}/${buf.length}` });
      if (a === 2 * MB && !dropped) { dropped = true; res.write(buf.subarray(a, a + 1000)); setTimeout(() => q.socket.destroy(), 4000); return; }
      res.end(buf.subarray(a, b + 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      assert.ok(ev.some((e) => e.event === 'signed-refresh'), 'signed link was refreshed');
      assert.equal(H.sha256(out), hash);
    } finally {
      s.close();
    }
  });

  it('unknown probe total falls back to single-stream', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-unknown-total');
    const s = http.createServer((q, res) => {
      if (q.headers.range) { res.writeHead(206, { 'Content-Range': 'bytes 0-0/*', 'Content-Length': 1 }); res.end('A'); }
      else { res.writeHead(200, { 'Content-Length': 4 }); res.end('AAAA'); }
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const t0 = Date.now();
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/live`, '-o', out, '--json', '--max-retries', '3'], { cwd: work });
      assert.ok(Date.now() - t0 < 30000, 'no retry storm on unknown total');
      assert.equal(r.code, 0);
      assert.equal(fs.readFileSync(out, 'utf8'), 'AAAA');
    } finally {
      s.close();
    }
  });

  it('DNS failure aborts fast', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-dns');
    const t0 = Date.now();
    const r = await H.runAccel(['http://nonexistent-host.invalid/f.bin', '-o', path.join(work, 'o.bin'), '--json', '--max-retries', '3'], { cwd: work });
    assert.ok(Date.now() - t0 < 60000, 'DNS failure must not retry for ~49 minutes');
    assert.equal(r.code, 1);
    assert.match(r.stdout + r.stderr, /ENOTFOUND|Probe failed/);
  });

  it('--max-retries 0 means a single attempt', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-maxr0');
    const t0 = Date.now();
    const r = await H.runAccel(['http://127.0.0.1:1/x', '-o', path.join(work, 'o.bin'), '--json', '--max-retries', '0'], { cwd: work, timeoutMs: 30000 });
    assert.ok(!r.timedOut, 'must finish, not hang');
    assert.ok(Date.now() - t0 < 25000);
    assert.equal(r.code, 1);
  });

  it('-o directory ends with a clean error event, not a crash', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-isdir');
    const src = H.makeFile(work, 'src.bin', 1 * MB);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      fs.mkdirSync(path.join(work, 'adir'));
      const r = await H.runAccel([srv.url('/f.bin'), '-o', 'adir', '-n', '2', '--json', '--max-retries', '1'], { cwd: work });
      assert.equal(r.code, 1);
      const ev = H.events(r.stdout); // throws if stdout is not pure NDJSON
      assert.ok(ev.some((e) => e.event === 'error'), 'final error event present');
    } finally {
      await srv.close();
    }
  });

  it('kill keeps byte-level progress in the manifest', { timeout: 180000 }, async () => {
    const work = H.workdir('rel-manifest');
    const crypto = require('crypto');
    const buf = crypto.randomBytes(40 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let served = 0;
    const ranges = [];
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      if (m) ranges.push([a, b]);
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, b - off + 1);
        served += n;
        res.write(buf.subarray(off, off + n));
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, 100); // ~640KB/s per chunk: 40MB takes ~16s
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const fileUrl = `http://127.0.0.1:${s.address().port}/f.bin`;
      const out = path.join(work, 'o.bin');
      const c = spawn('node', [H.AGENT_DLA, fileUrl, '-o', out, '-n', '4'], { cwd: work });
      const closed = new Promise((r) => c.on('close', r));
      await H.sleep(4500); // 10MB chunks at ~4MB/s: mid-flight
      c.kill();
      await closed;
      assert.ok(fs.existsSync(out + '.partial'), 'partial kept after kill');
      const m = JSON.parse(fs.readFileSync(out + '.manifest.json', 'utf8'));
      const kept = (m.done || []).reduce((t, [s2, e]) => t + (e - s2 + 1), 0)
        + Object.values(m.active || {}).reduce((t, [s2, x]) => t + Math.max(0, x - s2), 0);
      assert.ok(kept > 0, 'manifest records transferred bytes');
      served = 0;
      ranges.length = 0;
      const r = await H.runAccel([fileUrl, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), hash);
      // Resume proof: the rerun must transfer strictly less than a full
      // re-download. (A tighter bound against `kept` flaked under load: the
      // server counter includes bytes written to sockets it has not yet
      // noticed are dead. The deterministic ranges⊆gaps check below is the
      // precise invariant.)
      assert.ok(served < 40 * MB, `rerun resumed (${(served / MB).toFixed(1)}MB of 40MB)`);
      // Deterministic invariant (immune to timing flakiness): every byte the
      // rerun requested outside the 1-byte probe was missing per the manifest.
      const ivs = [...(m.done || []), ...Object.values(m.active || {})
        .filter((a) => Array.isArray(a) && a[1] > a[0]).map(([s, x]) => [s, x - 1])];
      ivs.sort((a, b) => a[0] - b[0]);
      const merged = [];
      for (const [a, b] of ivs) {
        const l = merged[merged.length - 1];
        if (l && a <= l[1] + 1) l[1] = Math.max(l[1], b);
        else merged.push([a, b]);
      }
      const gaps = [];
      let cur = 0;
      for (const [s, e] of merged) {
        if (s > cur) gaps.push([cur, s - 1]);
        cur = Math.max(cur, e + 1);
      }
      if (cur < 40 * MB) gaps.push([cur, 40 * MB - 1]);
      for (const [a, b] of ranges) {
        if (a === 0 && b === 0) continue; // probe
        assert.ok(gaps.some(([s, e]) => s <= a && b <= e),
          `rerun requested [${a}, ${b}], outside manifest gaps`);
      }
    } finally {
      s.close();
    }
  });

  it('cwd config cannot run harvestScript; explicit --config can', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-cfgtrust');
    const src = H.makeFile(work, 'src.bin', 1 * MB);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      fs.writeFileSync(path.join(work, 'agent-dla.json'), JSON.stringify({ proxies: 'px.txt', harvestScript: 'evil.js' }));
      fs.writeFileSync(path.join(work, 'px.txt'), '');
      fs.writeFileSync(path.join(work, 'evil.js'), "require('fs').writeFileSync('PWNED', 'x');\n");
      const out = path.join(work, 'o.bin');
      let r = await H.runAccel([srv.url('/f.bin'), '-o', out], { cwd: work, env: { AGENT_DLA_NO_AUTO_REFRESH: '1' } });
      assert.equal(r.code, 0);
      assert.ok(!fs.existsSync(path.join(work, 'PWNED')), 'cwd config must not execute harvestScript');
      assert.match(r.stderr, /ignoring sensitive/);
      try { fs.unlinkSync(out); } catch {}
      r = await H.runAccel([srv.url('/f.bin'), '-o', out, '--config', path.join(work, 'agent-dla.json')], { cwd: work });
      assert.equal(r.code, 0);
      assert.ok(fs.existsSync(path.join(work, 'PWNED')), 'explicit --config opts in');
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('bare ip:port proxy lines are used, not trashed', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-bareproxy');
    let proxied = 0;
    const px = http.createServer((cq, cr) => {
      proxied++;
      const t = new URL(cq.url);
      const pr = http.request({ host: t.hostname, port: t.port, path: t.pathname, headers: cq.headers }, (r) => { cr.writeHead(r.statusCode, r.headers); r.pipe(cr); });
      pr.end();
    });
    await new Promise((ok) => px.listen(0, '127.0.0.1', ok));
    const src = H.makeFile(work, 'src.bin', 1 * MB);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), `127.0.0.1:${px.address().port}\n`);
      fs.writeFileSync(path.join(work, 'h.js'), "require('fs').writeFileSync(process.argv[2], '# harvested\n');");
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '--json'], {
        cwd: work,
        env: { AGENT_DLA_HARVEST_SCRIPT: path.join(work, 'h.js'), AGENT_DLA_HARVEST_TIMEOUT_MS: '15000' },
      });
      assert.equal(r.code, 0);
      assert.ok(proxied > 0, 'working bare-ip:port proxy actually receives requests');
      assert.ok(!fs.readFileSync(path.join(work, 'proxies.txt'), 'utf8').includes('# harvested'), 'healthy list is not rewritten');
      assert.equal(H.sha256(out), src.hash);
    } finally {
      px.close();
      await srv.close();
    }
  });

  it('batch URLs sharing a basename get unique outputs', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-batchuniq');
    const A = Buffer.alloc(1000, 65);
    const B = Buffer.alloc(1000, 66);
    const s = http.createServer((q, res) => {
      const d = q.url.includes('id=2') ? B : A;
      res.writeHead(200, { 'Content-Length': d.length });
      res.end(d);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const base = `http://127.0.0.1:${s.address().port}`;
      fs.writeFileSync(path.join(work, 'list.txt'), `${base}/download?id=1\n${base}/download?id=2\n`);
      const r = await H.runAccel(['--list', 'list.txt', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      assert.equal(ev.find((e) => e.event === 'batch-done').completed, 2);
      const outs = ev.filter((e) => e.event === 'done').map((e) => e.output);
      assert.equal(new Set(outs).size, 2, 'distinct outputs');
      assert.ok(outs.some((o) => fs.readFileSync(o).equals(A)) && outs.some((o) => fs.readFileSync(o).equals(B)), 'both contents present');
    } finally {
      s.close();
    }
  });

  it('-n above 32 opens at most 32 concurrent transfers', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-conc');
    const MB = 1048576;
    const big = require('crypto').randomBytes(8 * MB);
    const bigHash = require('crypto').createHash('sha256').update(big).digest('hex');
    let cur = 0, max = 0;
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      if (!m) { res.writeHead(200, { 'Content-Length': big.length }); res.end(big); return; }
      const a = +m[1], b = +m[2];
      cur++;
      max = Math.max(max, cur);
      res.writeHead(206, { 'Content-Range': `bytes ${a}-${b}/${big.length}`, 'Content-Length': b - a + 1 });
      setTimeout(() => { res.end(big.subarray(a, b + 1)); cur--; }, a === 0 && b === 0 ? 0 : 300);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/big.bin`, '-o', out, '-n', '64', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.ok(max <= 32, `at most 32 concurrent (saw ${max})`);
      assert.equal(H.sha256(out), bigHash);
    } finally {
      s.close();
    }
  });

  it('--header reaches the origin but never the redirect target', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-header');
    const crypto = require('crypto');
    const buf = crypto.randomBytes(2 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    const seen1 = [], seen2 = [], seenPx = [];
    const s2 = require('http').createServer((q, res) => {
      seen2.push(q.headers['x-token'] || null);
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      res.end(buf.subarray(a, b + 1));
    });
    await new Promise((ok) => s2.listen(0, '127.0.0.1', ok));
    const url2 = `http://127.0.0.1:${s2.address().port}/file`;
    const s1 = require('http').createServer((q, res) => {
      seen1.push(q.headers['x-token'] || null);
      if (q.headers['x-token'] !== 's3cr3t') { res.writeHead(403); res.end('nope'); return; }
      res.writeHead(302, { Location: url2 }); res.end();
    });
    await new Promise((ok) => s1.listen(0, '127.0.0.1', ok));
    // recording forward proxy: the bench path must not hand it the token either
    const px = await H.startForwardProxy((clientReq, clientRes) => {
      seenPx.push(clientReq.headers['x-token'] || null);
      const t = new URL(clientReq.url);
      const preq = http.request({ host: t.hostname, port: t.port, path: t.pathname + t.search, method: 'GET', headers: { range: clientReq.headers.range } }, (r) => { clientRes.writeHead(r.statusCode, r.headers); r.pipe(clientRes); });
      preq.on('error', () => { try { clientRes.writeHead(502); clientRes.end(); } catch {} });
      preq.end();
    });
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), `http://127.0.0.1:${px.port}\n`);
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s1.address().port}/file`, '-o', out, '-n', '4', '--json', '--header', 'X-Token: s3cr3t', '--no-auto-refresh'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), hash);
      assert.ok(seen1.length > 0 && seen1.every((v) => v === 's3cr3t'), 'origin got the token');
      assert.ok(seen2.length > 0 && seen2.every((v) => v === null || v === undefined), 'redirect target never saw the token');
      assert.ok(seenPx.length > 0 && seenPx.every((v) => v === null || v === undefined), 'bench via proxy never saw the token');
    } finally {
      s1.close();
      s2.close();
      px.close();
    }
  });

  it('--deadline aborts a slow download', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-deadline');
    const big = Buffer.alloc(32 * MB, 9);
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : big.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${big.length}` } : {}) });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, b - off + 1);
        res.write(big.subarray(off, off + n));
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, 200); // ~320KB/s: 32MB takes ~100s
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const t0 = Date.now();
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/big`, '-o', path.join(work, 'o.bin'), '-n', '2', '--json', '--deadline', '3000'], { cwd: work });
      const secs = (Date.now() - t0) / 1000;
      assert.equal(r.code, 1);
      assert.ok(secs < 15, `deadline enforced (took ${secs.toFixed(1)}s)`);
      assert.match(r.stdout + r.stderr, /deadline/);
    } finally {
      s.close();
    }
  });

  it('proxy passing the bench but 403ing chunks is evicted', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-403evict');
    const src = H.makeFile(work, 'src.bin', 2 * MB);
    const buf = fs.readFileSync(src.path);
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } });
    // proxy: serves the 64KB bench sample correctly, 403s everything else
    const px = await H.startForwardProxy((clientReq, clientRes) => {
      const m = /bytes=(\d+)-(\d*)/.exec(clientReq.headers.range || '');
      if (m && +m[2] - +m[1] + 1 <= 65536 && +m[1] === 0) {
        const t = new URL(clientReq.url);
        const preq = http.request({ host: t.hostname, port: t.port, path: t.pathname, method: 'GET', headers: { range: clientReq.headers.range } }, (r) => { clientRes.writeHead(r.statusCode, r.headers); r.pipe(clientRes); });
        preq.on('error', () => { try { clientRes.writeHead(502); clientRes.end(); } catch {} });
        preq.end();
        return;
      }
      clientRes.writeHead(403, { 'Content-Type': 'text/html' });
      clientRes.end('<h1>blocked</h1>');
    });
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), `http://127.0.0.1:${px.port}\n`);
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2', '--json', '--no-auto-refresh'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
      const ev = H.events(r.stdout);
      assert.ok(ev.filter((e) => e.event === 'chunk-done').length >= 2);
    } finally {
      px.close();
      await srv.close();
    }
  });

  it('--max-retries 0 fails chunk attempts fast', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-maxr0chunk');
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      if (m && +m[1] === 0 && +m[2] === 0) {
        res.writeHead(206, { 'Content-Range': 'bytes 0-0/1000', 'Content-Length': 1 });
        res.end('A');
        return;
      }
      if (m) { res.writeHead(500); res.end('boom'); return; }
      res.writeHead(200, { 'Content-Length': 1000, 'Accept-Ranges': 'bytes' });
      res.end(Buffer.alloc(1000, 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const t0 = Date.now();
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f`, '-o', path.join(work, 'o.bin'), '-n', '2', '--json', '--max-retries', '0'], { cwd: work });
      assert.ok(Date.now() - t0 < 30000);
      assert.equal(r.code, 1);
    } finally {
      s.close();
    }
  });

  it('same-size stranger file without proof is redownloaded, then cached', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-collide');
    const src = H.makeFile(work, 'src.bin', 1 * MB);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      const out = path.join(work, 'o.bin');
      fs.writeFileSync(out, crypto.randomBytes(1 * MB)); // stranger, same size
      let r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash, 'stranger content replaced by server content');
      r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.ok(H.events(r.stdout).some((e) => e.event === 'done' && e.cached === true), 'receipt makes rerun cached');
    } finally {
      await srv.close();
    }
  });

  it('mirror serving different bytes is evicted at the content check', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-evilmirror');
    const src = H.makeFile(work, 'src.bin', 2 * MB);
    const buf = fs.readFileSync(src.path);
    const evil = Buffer.from(buf);
    evil[100] ^= 0xff;
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } });
    const msrv = await H.startServer({ '/f.bin': { buf: evil, tmp: path.join(work, 'srv2.tmp') } });
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '--mirror', msrv.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
      assert.match(r.stderr, /content check, evicted/);
    } finally {
      await srv.close();
      await msrv.close();
    }
  });

  it('--overwrite truncates instead of appending to a stranger file', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-overwrite');
    const buf = crypto.randomBytes(1 * MB);
    // single-stream server: ignores Range, always serves the whole file
    const s = require('http').createServer((q, res) => {
      res.writeHead(200, { 'Content-Length': buf.length });
      res.end(buf);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      fs.writeFileSync(out, crypto.randomBytes(100)); // stranger, smaller
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f.bin`, '-o', out, '-n', '1', '--json', '--overwrite'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(fs.statSync(out).size, buf.length);
      assert.ok(fs.readFileSync(out).equals(buf), 'output equals the server file exactly');
    } finally {
      s.close();
    }
  });

  it('--deadline in batch mode stops file 1 before file 2 starts', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-batchdeadline');
    const hits1 = [], hits2 = [];
    const slow = require('http').createServer((q, res) => {
      hits1.push(Date.now());
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : 32 * MB - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${32 * MB}` } : {}) });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, b - off + 1);
        res.write(Buffer.alloc(n, 7));
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, 200);
      };
      tick();
    });
    await new Promise((ok) => slow.listen(0, '127.0.0.1', ok));
    const fastBuf = crypto.randomBytes(1 * MB);
    const fast = require('http').createServer((q, res) => {
      hits2.push(Date.now());
      res.writeHead(200, { 'Content-Length': fastBuf.length });
      res.end(fastBuf);
    });
    await new Promise((ok) => fast.listen(0, '127.0.0.1', ok));
    try {
      fs.writeFileSync(path.join(work, 'list.txt'),
        `http://127.0.0.1:${slow.address().port}/slow.bin\nhttp://127.0.0.1:${fast.address().port}/fast.bin\n`);
      const r = await H.runAccel(['--list', 'list.txt', '--json', '--deadline', '3000'], { cwd: work });
      assert.equal(r.code, 1, 'file 1 fails, file 2 completes');
      const ev = H.events(r.stdout);
      assert.ok(ev.some((e) => e.event === 'error' && /deadline/.test(e.message || '')), 'deadline error reported');
      assert.ok(ev.some((e) => e.event === 'done' && !e.cached), 'file 2 completed');
      assert.ok(hits1.length > 0 && hits2.length > 0);
      assert.ok(Math.max(...hits1) < Math.min(...hits2), 'no file-1 requests after file 2 started');
    } finally {
      slow.close();
      fast.close();
    }
  });

  it('stale fallback does not drain full bodies (bandwidth bounded)', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-stalebw');
    const buf = crypto.randomBytes(4 * MB);
    let served = 0;
    let rangeReqs = 0;
    const s = require('http').createServer((q, res) => {
      const w = res.write.bind(res);
      const e = res.end.bind(res);
      const live = () => !res.destroyed && !q.socket.destroyed;
      // paced drip: bytes only count if the client is still listening,
      // so destroying a response actually saves bandwidth
      const drip = (data) => {
        let off = 0;
        res.on('error', () => {});
        const tick = () => {
          if (!live()) return;
          const n = Math.min(64 * 1024, data.length - off);
          if (n > 0) { served += n; w(data.subarray(off, off + n)); off += n; }
          if (off >= data.length) { if (live()) e(); }
          else setTimeout(tick, 50);
        };
        tick();
      };
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      if (m && +m[1] === 0 && +m[2] === 0) {
        res.writeHead(206, { 'Content-Range': `bytes 0-0/${buf.length}`, 'Content-Length': 1 });
        res.end(buf.subarray(0, 1));
        return;
      }
      rangeReqs++;
      if (rangeReqs <= 2) {
        const a = +m[1], b = +m[2];
        res.writeHead(206, { 'Content-Length': b - a + 1, 'Content-Range': `bytes ${a}-${b}/${buf.length}` });
        drip(buf.subarray(a, b + 1));
        return;
      }
      // server "changed": ignores Range, full 200 body (destroyed at headers)
      res.writeHead(200, { 'Content-Length': buf.length });
      drip(buf);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f.bin`, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), crypto.createHash('sha256').update(buf).digest('hex'));
      assert.ok(served <= 2 * buf.length, `transferred ${served} for a ${buf.length} file (stale drain bounded)`);
    } finally {
      s.close();
    }
  });

  it('single-stream follows redirects on the final URL', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-singleredirect');
    const buf = crypto.randomBytes(1 * MB);
    const s = require('http').createServer((q, res) => {
      if (q.url === '/start') { res.writeHead(302, { Location: '/cdn/file' }); res.end(); return; }
      res.writeHead(200, { 'Content-Length': buf.length });
      res.end(buf);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/start`, '-o', out, '-n', '1', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.ok(fs.readFileSync(out).equals(buf));
    } finally {
      s.close();
    }
  });

  it('republished same-size file restarts clean with the new version', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-republish');
    const crypto2 = require('crypto');
    const v1 = crypto2.randomBytes(4 * MB);
    const v2 = crypto2.randomBytes(4 * MB);
    const h2 = crypto2.createHash('sha256').update(v2).digest('hex');
    const t0 = Date.now();
    const flipAt = t0 + 1200;
    const servePaced = (res, data, a, b, destroyAt) => {
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        if (destroyAt && Date.now() > destroyAt) { try { res.destroy(); } catch {} return; }
        const n = Math.min(64 * 1024, b - off + 1);
        res.write(data.subarray(off, off + n));
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, 250); // ~256KB/s: chunks stay in flight for seconds
      };
      tick();
    };
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      const cur = Date.now() > flipAt ? v2 : v1;
      const etag = Date.now() > flipAt ? '"v2"' : '"v1"';
      if (u.pathname === '/release') {
        res.writeHead(302, { Location: `/signed?exp=${Date.now() + 1500}` });
        res.end();
        return;
      }
      if (Date.now() > +u.searchParams.get('exp')) { res.writeHead(403); res.end('expired'); return; }
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : cur.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ETag: etag, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${cur.length}` } : {}) });
      // one chunk gets cut off after expiry, forcing a refresh onto v2
      const killAt = (a === 2 * MB && etag === '"v1"') ? t0 + 2000 : 0;
      servePaced(res, cur, a, b, killAt);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), h2, 'output is the new version, not a mix');
    } finally {
      s.close();
    }
  });

  it('--max-retries 0 issues exactly one round of chunk attempts', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-maxr0count');
    let chunkHits = 0;
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      if (m && +m[1] === 0 && +m[2] === 0) {
        res.writeHead(206, { 'Content-Range': 'bytes 0-0/1000', 'Content-Length': 1 });
        res.end('A');
        return;
      }
      if (m) { chunkHits++; res.writeHead(500); res.end('boom'); return; }
      res.writeHead(200, { 'Content-Length': 1000, 'Accept-Ranges': 'bytes' });
      res.end(Buffer.alloc(1000, 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f`, '-o', path.join(work, 'o.bin'), '-n', '2', '--json', '--max-retries', '0'], { cwd: work });
      assert.equal(r.code, 1);
      assert.equal(chunkHits, 4, 'one attempt + one last-resort per chunk, then stop');
    } finally {
      s.close();
    }
  });

  it('mirror differing only at the end is evicted by the tail sample', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-eviltail');
    const src = H.makeFile(work, 'src.bin', 2 * MB);
    const buf = fs.readFileSync(src.path);
    const evil = Buffer.from(buf);
    evil[evil.length - 100] ^= 0xff;
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } });
    const msrv = await H.startServer({ '/f.bin': { buf: evil, tmp: path.join(work, 'srv2.tmp') } });
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '--mirror', msrv.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
      assert.match(r.stderr, /content check, evicted/);
    } finally {
      await srv.close();
      await msrv.close();
    }
  });

  it('single-stream resume after republish downloads the new version', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-singlechange');
    const crypto2 = require('crypto');
    const v1 = crypto2.randomBytes(4 * MB);
    const v2 = crypto2.randomBytes(4 * MB);
    const h2 = crypto2.createHash('sha256').update(v2).digest('hex');
    const t0 = Date.now();
    const flipAt = t0 + 1000;
    const liveSockets = new Set();
    const s = require('http').createServer((q, res) => {
      liveSockets.add(q.socket);
      q.socket.on('close', () => liveSockets.delete(q.socket));
      const cur = Date.now() > flipAt ? v2 : v1;
      const etag = Date.now() > flipAt ? '"w2"' : '"w1"';
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : cur.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ETag: etag, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${cur.length}` } : {}) });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, b - off + 1);
        res.write(cur.subarray(off, off + n));
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, 50); // ~1.3MB/s: 4MB takes ~3s
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    // kill all in-flight sockets mid-run: the resume carries If-Range into v2
    setTimeout(() => { for (const sock of liveSockets) { try { sock.destroy(); } catch {} } }, 2000);
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f.bin`, '-o', out, '-n', '1', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), h2, 'output is exactly the new version, not a mix');
    } finally {
      s.close();
    }
  });

  it('revoked signed link fails fast instead of retrying ~49 minutes', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-revoked');
    const t0 = Date.now();
    let releases = 0;
    let dropped = false;
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      if (u.pathname === '/release') {
        releases++;
        if (releases > 1) { res.writeHead(403); res.end('revoked'); return; }
        res.writeHead(302, { Location: `/signed?exp=${Date.now() + 800}` });
        res.end();
        return;
      }
      if (Date.now() > +u.searchParams.get('exp')) { res.writeHead(403); res.end('expired'); return; }
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : 4 * MB - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${4 * MB}` } : {}) });
      // drop one chunk after expiry so its retry hits the expired link
      // (skips the 1-byte probe)
      if (m && (b - a) > 100 && !dropped) {
        dropped = true;
        res.write(Buffer.alloc(1000, 5));
        setTimeout(() => { try { q.socket.destroy(); } catch {} }, Math.max(0, t0 + 2000 - Date.now()));
        return;
      }
      const body = Buffer.alloc(b - a + 1, 5);
      let off = 0;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, body.length - off);
        res.write(body.subarray(off, off + n));
        off += n;
        if (off >= body.length) res.end();
        else setTimeout(tick, 250); // ~256KB/s: expiry (0.8s) hits mid-run
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const t0 = Date.now();
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', path.join(work, 'o.bin'), '-n', '4', '--json'], { cwd: work });
      const secs = (Date.now() - t0) / 1000;
      assert.equal(r.code, 1);
      assert.ok(secs < 30, `revoked link fails fast (took ${secs.toFixed(1)}s)`);
      assert.match(r.stdout + r.stderr, /403|revoked|refresh failed/);
    } finally {
      s.close();
    }
  });

  it('--deadline cuts a 100s Retry-After wait', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-retryafter-dl');
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      if (m && +m[1] === 0 && +m[2] === 0) {
        res.writeHead(206, { 'Content-Range': 'bytes 0-0/1000', 'Content-Length': 1 });
        res.end('A');
        return;
      }
      res.writeHead(429, { 'Retry-After': '100' });
      res.end('slow down');
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const t0 = Date.now();
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f`, '-o', path.join(work, 'o.bin'), '-n', '2', '--json', '--deadline', '3000'], { cwd: work });
      const secs = (Date.now() - t0) / 1000;
      assert.equal(r.code, 1);
      assert.ok(secs < 10, `deadline enforced (took ${secs.toFixed(1)}s)`);
      assert.match(r.stdout + r.stderr, /deadline/);
    } finally {
      s.close();
    }
  });

  it('--deadline bounds a 60s harvest', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-harvest-dl');
    const src = H.makeFile(work, 'src.bin', 1 * MB);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), 'http://127.0.0.1:1\n');
      fs.writeFileSync(path.join(work, 'sleeper.js'), 'setTimeout(() => {}, 60000);\n');
      const t0 = Date.now();
      const r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'o.bin'), '-n', '2', '--json', '--deadline', '3000'], {
        cwd: work,
        env: { AGENT_DLA_HARVEST_SCRIPT: path.join(work, 'sleeper.js') },
      });
      const secs = (Date.now() - t0) / 1000;
      // The harvest eats the whole budget, so the download itself must fail
      // with deadline rather than run 60s+ over budget.
      assert.equal(r.code, 1);
      assert.ok(secs < 12, `harvest bounded by deadline (took ${secs.toFixed(1)}s)`);
      assert.match(r.stdout + r.stderr, /deadline/);
    } finally {
      await srv.close();
    }
  });

  it('flapping validators fall back to single-stream and complete', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-lbmtime');
    const buf = crypto.randomBytes(4 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let n = 0;
    const s = require('http').createServer((q, res) => {
      // RFC-strict on If-Range is not needed here: alternate Last-Modified
      // on every response while serving identical bytes from "backends".
      n++;
      const mtime = n % 2 ? 'Wed, 01 Jan 2025 00:00:00 GMT' : 'Thu, 02 Jan 2025 00:00:00 GMT';
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, 'Last-Modified': mtime, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      res.end(buf.subarray(a, b + 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f.bin`, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), hash);
    } finally {
      s.close();
    }
  });

  it('corrupt per-file receipt with -o re-downloads cleanly', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-receiptcorrupt');
    const src = H.makeFile(work, 'src.bin', 1 * MB);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      const out = path.join(work, 'o.bin');
      const r1 = await H.runAccel([srv.url('/f.bin'), '-o', out, '--json'], { cwd: work });
      assert.equal(r1.code, 0);
      // corrupt just this file's receipt (per-file store, not a shared index)
      fs.writeFileSync(path.join(work, '.agent-dla', 'receipts', 'o.bin.json'), '{corrupt!!!');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('corrupt per-file receipt without -o is refused, siblings stay cached', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-receiptsiblings');
    const src1 = H.makeFile(work, 'src1.bin', 1 * MB);
    const src2 = H.makeFile(work, 'src2.bin', 1 * MB);
    const srv = await H.startServer({
      '/f1.bin': { buf: fs.readFileSync(src1.path), tmp: path.join(work, 'srv1.tmp') },
      '/f2.bin': { buf: fs.readFileSync(src2.path), tmp: path.join(work, 'srv2.tmp') },
    });
    try {
      const r1 = await H.runAccel([srv.url('/f1.bin'), '--json'], { cwd: work });
      const r2 = await H.runAccel([srv.url('/f2.bin'), '--json'], { cwd: work });
      assert.equal(r1.code, 0);
      assert.equal(r2.code, 0);
      // corrupt only f1's receipt
      fs.writeFileSync(path.join(work, '.agent-dla', 'receipts', 'f1.bin.json'), '{corrupt!!!');
      const rr1 = await H.runAccel([srv.url('/f1.bin'), '--json'], { cwd: work });
      assert.equal(rr1.code, 1, 'corrupt receipt without -o must refuse, not overwrite');
      assert.match(rr1.stdout + rr1.stderr, /--overwrite/);
      const rr2 = await H.runAccel([srv.url('/f2.bin'), '--json'], { cwd: work });
      assert.equal(rr2.code, 0);
      assert.ok(H.events(rr2.stdout).some((e) => e.event === 'done' && e.cached === true), 'sibling stays cached');
    } finally {
      await srv.close();
    }
  });

  it('no receipt never overwrites an unrelated same-size file', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-receiptclobber');
    const src = H.makeFile(work, 'src.bin', 1 * MB);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      const victim = path.join(work, 'f.bin');
      const stranger = crypto.randomBytes(1 * MB);
      fs.writeFileSync(victim, stranger);
      const r = await H.runAccel([srv.url('/f.bin'), '--json'], { cwd: work });
      assert.equal(r.code, 1);
      assert.match(r.stdout + r.stderr, /--overwrite/);
      assert.equal(fs.readFileSync(victim).toString('hex'), stranger.toString('hex'), 'unrelated file untouched');
    } finally {
      await srv.close();
    }
  });

  it('parallel downloads keep all receipts, reruns cached', { timeout: 180000 }, async () => {
    const work = H.workdir('rel-parallel-receipts');
    const files = {};
    const srcs = [];
    for (let i = 0; i < 8; i++) {
      const s = H.makeFile(work, `src${i}.bin`, 1 * MB);
      srcs.push(s);
      files[`/f${i}.bin`] = { buf: fs.readFileSync(s.path), tmp: path.join(work, `srv${i}.tmp`) };
    }
    const srv = await H.startServer(files);
    try {
      const outs = srcs.map((_, i) => path.join(work, `o${i}.bin`));
      const first = await Promise.all(outs.map((out, i) =>
        H.runAccel([srv.url(`/f${i}.bin`), '-o', out, '-n', '2', '--json'], { cwd: work })));
      for (const r of first) assert.equal(r.code, 0);
      for (let i = 0; i < 8; i++) assert.equal(H.sha256(outs[i]), srcs[i].hash);
      const second = await Promise.all(outs.map((out, i) =>
        H.runAccel([srv.url(`/f${i}.bin`), '-o', out, '-n', '2', '--json'], { cwd: work })));
      for (const r of second) {
        assert.equal(r.code, 0);
        assert.ok(H.events(r.stdout).some((e) => e.event === 'done' && e.cached === true), 'rerun cached');
      }
    } finally {
      await srv.close();
    }
  });

  it('strict If-Range server resumes single-stream without restart', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-strict-ifrange');
    const buf = crypto.randomBytes(4 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    const ETAG = '"strict1"';
    let seenIfRange = null;
    let droppedOnce = false;
    let wireBytes = 0;
    const s = require('http').createServer((q, res) => {
      const ir = q.headers['if-range'];
      const range = q.headers.range || '';
      const m = /bytes=(\d+)-(\d*)/.exec(range);
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      if (range === 'bytes=0-0') {
        // probe: always succeed, never drop
        res.writeHead(206, { 'Content-Length': 1, 'Content-Range': `bytes 0-0/${buf.length}`, ETag: ETAG });
        res.end(buf.subarray(0, 1));
        return;
      }
      if (!droppedOnce) {
        // first download attempt (single-stream 200, no Range): send 1MB then kill
        droppedOnce = true;
        res.writeHead(m ? 206 : 200, { 'Content-Length': buf.length - a, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}), ETag: ETAG });
        res.write(buf.subarray(a, a + 1 * MB));
        wireBytes += 1 * MB;
        setTimeout(() => { try { q.socket.destroy(); } catch {} }, 100);
        return;
      }
      if (m) {
        seenIfRange = ir || null;
        if (ir !== ETAG) {
          // strict server: unrecognized If-Range -> full 200, resume becomes restart
          res.writeHead(200, { 'Content-Length': buf.length, ETag: ETAG });
          wireBytes += buf.length;
          res.end(buf);
          return;
        }
        res.writeHead(206, { 'Content-Length': b - a + 1, 'Content-Range': `bytes ${a}-${b}/${buf.length}`, ETag: ETAG });
        wireBytes += b - a + 1;
        res.end(buf.subarray(a, b + 1));
        return;
      }
      res.writeHead(200, { 'Content-Length': buf.length, ETag: ETAG });
      wireBytes += buf.length;
      res.end(buf);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f.bin`, '-o', out, '-n', '1', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), hash);
      assert.equal(seenIfRange, ETAG, 'If-Range carries the strong ETag, not [object Object]');
      assert.ok(wireBytes < buf.length * 1.2, `resumed, not restarted (wire ${wireBytes} < ${Math.round(buf.length * 1.2)})`);
    } finally {
      s.close();
    }
  });

  it('URL credentials never reach a plain-http proxy', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-userinfo-proxy');
    const src = H.makeFile(work, 'src.bin', 1 * MB);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    let sawAuth = 0, total = 0;
    const proxy = http.createServer((clientReq, clientRes) => {
      total++;
      if (clientReq.headers.authorization) sawAuth++;
      let target;
      try { target = new URL(clientReq.url); } catch { clientRes.writeHead(400); clientRes.end(); return; }
      const headers = { ...clientReq.headers };
      delete headers['proxy-authorization'];
      delete headers['proxy-connection'];
      delete headers.authorization; // must not forward what we must not have seen
      headers.host = target.host;
      const preq = http.request(
        { host: target.hostname, port: target.port || 80, path: target.pathname + target.search, method: clientReq.method, headers },
        (pres) => { clientRes.writeHead(pres.statusCode, pres.headers); pres.pipe(clientRes); },
      );
      preq.on('error', () => { try { clientRes.writeHead(502); clientRes.end(); } catch {} });
      clientReq.pipe(preq);
    });
    await new Promise((ok) => proxy.listen(0, '127.0.0.1', ok));
    try {
      const authed = srv.url('/f.bin').replace('http://', 'http://user:pw@');
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([authed, '-o', out, '-n', '2', '--json', '--no-auto-refresh',
        '-p', (() => { const f = path.join(work, 'proxies.txt'); fs.writeFileSync(f, `http://127.0.0.1:${proxy.address().port}\n`); return f; })(),
      ], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
      assert.ok(total > 0, 'proxy saw traffic');
      assert.equal(sawAuth, 0, 'proxy never saw Authorization');
    } finally {
      proxy.close();
      await srv.close();
    }
  });

  it('query-selected files never share a receipt (cached path)', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-querycollide');
    const b1 = crypto.randomBytes(2 * MB);
    const b2 = crypto.randomBytes(2 * MB);
    const h1 = crypto.createHash('sha256').update(b1).digest('hex');
    const h2 = crypto.createHash('sha256').update(b2).digest('hex');
    // Same path, same size, no validators, no disposition: the query alone
    // selects the content. Server-chosen name is f.bin for both.
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      const cur = u.searchParams.get('id') === '2' ? b2 : b1;
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : cur.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${cur.length}` } : {}) });
      res.end(cur.subarray(a, b + 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const base = `http://127.0.0.1:${s.address().port}/f.bin`;
      const r1 = await H.runAccel([`${base}?id=1`, '--json'], { cwd: work });
      assert.equal(r1.code, 0);
      assert.equal(H.sha256(path.join(work, 'f.bin')), h1);
      // Second query must NOT report cached with id=1's bytes. Without -o the
      // guard refuses (safe); with --overwrite it fetches id=2 exactly.
      const r2 = await H.runAccel([`${base}?id=2`, '--json'], { cwd: work });
      assert.equal(r2.code, 1, 'different query, no receipt: refuse, never wrong-bytes-exit-0');
      assert.equal(H.sha256(path.join(work, 'f.bin')), h1, 'refused run leaves id=1 untouched');
      const r3 = await H.runAccel([`${base}?id=2`, '--json', '--overwrite'], { cwd: work });
      assert.equal(r3.code, 0);
      assert.equal(H.sha256(path.join(work, 'f.bin')), h2, 'output is exactly id=2');
    } finally {
      s.close();
    }
  });

  it('query-selected files never share a manifest (resume path)', { timeout: 180000 }, async () => {
    const work = H.workdir('rel-querycollide-resume');
    const b1 = crypto.randomBytes(8 * MB);
    const b2 = crypto.randomBytes(8 * MB);
    const h2 = crypto.createHash('sha256').update(b2).digest('hex');
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      const cur = u.searchParams.get('id') === '2' ? b2 : b1;
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : cur.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${cur.length}` } : {}) });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, b - off + 1);
        res.write(cur.subarray(off, off + n));
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, 250); // ~256KB/s per chunk: the kill always lands mid-flight
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const base = `http://127.0.0.1:${s.address().port}/f.bin`;
      const out = path.join(work, 'o.bin');
      const c = spawn('node', [H.AGENT_DLA, `${base}?id=1`, '-o', out, '-n', '4'], { cwd: work });
      const closed = new Promise((r) => c.on('close', r));
      await H.sleep(2500);
      c.kill();
      await closed;
      assert.ok(fs.existsSync(out + '.partial'), 'partial kept after kill');
      const mk = JSON.parse(fs.readFileSync(out + '.manifest.json', 'utf8'));
      const kept = (mk.done || []).reduce((t, [x, y]) => t + (y - x + 1), 0)
        + Object.values(mk.active || {}).reduce((t, a) => t + (Array.isArray(a) ? Math.max(0, a[1] - a[0]) : 0), 0);
      assert.ok(kept > 0 && kept < 8 * MB, `kill landed mid-flight (kept ${(kept / MB).toFixed(1)}MB of 8MB)`);
      // ?id=2 must not reuse ?id=1's manifest: output must be exactly id=2.
      const r = await H.runAccel([`${base}?id=2`, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), h2, 'output is exactly id=2, no mixed blocks');
    } finally {
      s.close();
    }
  });

  it('shared strong ETag across queries never merges identities', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-queryetags');
    const b1 = crypto.randomBytes(2 * MB);
    const b2 = crypto.randomBytes(2 * MB);
    const h1 = crypto.createHash('sha256').update(b1).digest('hex');
    const h2 = crypto.createHash('sha256').update(b2).digest('hex');
    // Same path, same size, same STRONG ETag on different content (e.g. an
    // mtime-size ETag behind an X-Accel-Redirect endpoint). The query still
    // selects the resource: identities must differ.
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      const cur = u.searchParams.get('id') === '2' ? b2 : b1;
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : cur.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ETag: '"v1"', ...(m ? { 'Content-Range': `bytes ${a}-${b}/${cur.length}` } : {}) });
      res.end(cur.subarray(a, b + 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const base = `http://127.0.0.1:${s.address().port}/f.bin`;
      const r1 = await H.runAccel([`${base}?id=1`, '--json'], { cwd: work });
      assert.equal(r1.code, 0);
      assert.equal(H.sha256(path.join(work, 'f.bin')), h1);
      const r2 = await H.runAccel([`${base}?id=2`, '--json'], { cwd: work });
      assert.equal(r2.code, 1, 'shared ETag must not merge queries: refuse, never wrong-bytes-exit-0');
      assert.equal(H.sha256(path.join(work, 'f.bin')), h1, 'refused run leaves id=1 untouched');
      const r3 = await H.runAccel([`${base}?id=2`, '--json', '--overwrite'], { cwd: work });
      assert.equal(r3.code, 0);
      assert.equal(H.sha256(path.join(work, 'f.bin')), h2, 'output is exactly id=2');
    } finally {
      s.close();
    }
  });

  it('download tokens never share an identity (tokencollide)', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-tokencollide');
    const bA = crypto.randomBytes(2 * MB);
    const bB = crypto.randomBytes(2 * MB);
    const hA = crypto.createHash('sha256').update(bA).digest('hex');
    const hB = crypto.createHash('sha256').update(bB).digest('hex');
    // ?token= selects the file (download-token endpoints). It must stay in
    // the key: stripping it merges A and B into wrong-bytes-exit-0 (T1).
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      const cur = u.searchParams.get('token') === 'B' ? bB : bA;
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : cur.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${cur.length}` } : {}) });
      res.end(cur.subarray(a, b + 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const base = `http://127.0.0.1:${s.address().port}/download?token=`;
      const r1 = await H.runAccel([`${base}A`, '-o', path.join(work, 'model.bin'), '--json'], { cwd: work });
      assert.equal(r1.code, 0);
      assert.equal(H.sha256(path.join(work, 'model.bin')), hA);
      // Same -o, different token: no valid receipt, so a clean re-download of B.
      const r2 = await H.runAccel([`${base}B`, '-o', path.join(work, 'model.bin'), '--json'], { cwd: work });
      assert.equal(r2.code, 0);
      assert.equal(H.sha256(path.join(work, 'model.bin')), hB, 'output is exactly B, never cached A');
    } finally {
      s.close();
    }
  });

  it('download tokens never share a manifest (tokenresume)', { timeout: 180000 }, async () => {
    const work = H.workdir('rel-tokenresume');
    const bA = crypto.randomBytes(8 * MB);
    const bB = crypto.randomBytes(8 * MB);
    const hB = crypto.createHash('sha256').update(bB).digest('hex');
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      const cur = u.searchParams.get('token') === 'B' ? bB : bA;
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : cur.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${cur.length}` } : {}) });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, b - off + 1);
        res.write(cur.subarray(off, off + n));
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, 250); // ~256KB/s per chunk: the kill always lands mid-flight
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const base = `http://127.0.0.1:${s.address().port}/download?token=`;
      const out = path.join(work, 'model.bin');
      const c = spawn('node', [H.AGENT_DLA, `${base}A`, '-o', out, '-n', '4'], { cwd: work });
      const closed = new Promise((r) => c.on('close', r));
      await H.sleep(2500);
      c.kill();
      await closed;
      assert.ok(fs.existsSync(out + '.partial'), 'partial kept after kill');
      // token=B must not reuse token=A's manifest: output must be exactly B.
      const r = await H.runAccel([`${base}B`, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), hB, 'output is exactly B, no mixed blocks');
    } finally {
      s.close();
    }
  });

  it('refreshed presigned link without an ETag still resumes', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-presignresume');
    const buf = crypto.randomBytes(2 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    // Only signature/expiry params differ between refreshes; no ETag at all.
    // The stripped identity matches, so the rerun is cached, not redownloaded.
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      res.end(buf.subarray(a, b + 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const base = `http://127.0.0.1:${s.address().port}/f.bin`;
      const q1 = 'X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AK&X-Amz-Date=20250101&X-Amz-Expires=60&X-Amz-Signature=aaa&X-Amz-SignedHeaders=host';
      const q2 = 'X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AK&X-Amz-Date=20250102&X-Amz-Expires=60&X-Amz-Signature=bbb&X-Amz-SignedHeaders=host';
      const r1 = await H.runAccel([`${base}?${q1}`, '-o', path.join(work, 'o.bin'), '--json'], { cwd: work });
      assert.equal(r1.code, 0);
      const r2 = await H.runAccel([`${base}?${q2}`, '-o', path.join(work, 'o.bin'), '--json'], { cwd: work });
      assert.equal(r2.code, 0);
      assert.ok(H.events(r2.stdout).some((e) => e.event === 'done' && e.cached === true), 'refreshed link resumes via stripped identity');
      assert.equal(H.sha256(path.join(work, 'o.bin')), hash);
    } finally {
      s.close();
    }
  });

  it('one-off 403 on refresh recovers, persistent 403 still aborts (flap403)', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-flap403');
    const buf = crypto.randomBytes(4 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let releases = 0;
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      if (u.pathname === '/release') {
        releases++;
        if (releases === 2) { res.writeHead(403); res.end('flap'); return; } // one-off
        res.writeHead(302, { Location: `/signed?exp=${Date.now() + 1500}` });
        res.end();
        return;
      }
      if (Date.now() > +u.searchParams.get('exp')) { res.writeHead(403); res.end('expired'); return; }
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, b - off + 1);
        res.write(buf.subarray(off, off + n));
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, 120); // expiry (1.5s) hits mid-run, refresh flaps once
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), hash);
    } finally {
      s.close();
    }
  });

  // Signed-link server for the R1/R2 tests: /release 302s to a link that
  // lives `lifeMs`; data responses are paced and cut once at each time/offset
  // `cutAt` returns true for (a flaky network), so retries hit expired links.
  function signedLinkServer(buf, { lifeMs, pace, cutAt, release }) {
    const st = { refreshes: 0, served: 0, releases: 0, t0: Date.now() };
    const cut = new Set();
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      if (u.pathname === '/release') {
        st.releases++;
        const r = release ? release(st.releases) : null;
        if (r) { res.writeHead(r); res.end('no'); return; }
        res.writeHead(302, { Location: `/signed?exp=${Date.now() + lifeMs}` });
        res.end();
        return;
      }
      if (Date.now() > +u.searchParams.get('exp')) { res.writeHead(403); res.end('expired'); return; }
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const key = cutAt && cutAt(off, Date.now() - st.t0);
        if (key !== null && key !== undefined && key !== false && !cut.has(key)) { cut.add(key); q.socket.destroy(); return; }
        const n = Math.min(pace.bytes, b - off + 1);
        res.write(buf.subarray(off, off + n));
        st.served += n;
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, pace.ms);
      };
      tick();
    });
    return { s, st };
  }
  const refreshEvents = (r) => r.stdout.split('\n').filter((l) => l.includes('"signed-refresh"')).length;

  it('long download over short-lived links refreshes more than 5 times (R1)', { timeout: 180000 }, async () => {
    const work = H.workdir('rel-refresh-many');
    const buf = crypto.randomBytes(6 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    // -n 6 = six 1MB jobs at ~64KB/s. Job k's connection drops once at
    // 1.5s + 2.5s*k; its retry finds the 1s link expired and must refresh. Six
    // spaced drops = six successful refreshes, each followed by progress.
    const { s } = signedLinkServer(buf, {
      lifeMs: 1000,
      pace: { bytes: 16 * 1024, ms: 250 },
      cutAt: (off, el) => { const k = Math.floor(off / MB); return el > 1500 + 2500 * k ? k : null; },
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '6', '--json'], { cwd: work, timeoutMs: 170000 });
      assert.equal(r.code, 0, r.stderr.slice(-400));
      assert.equal(H.sha256(out), hash);
      assert.ok(refreshEvents(r) >= 6, `expected >= 6 successful refreshes, got ${refreshEvents(r)}`);
    } finally {
      s.close();
    }
  });

  it('refreshes that deliver nothing still hit the cap (R1 bound)', { timeout: 180000 }, async () => {
    const work = H.workdir('rel-refresh-dead');
    const buf = crypto.randomBytes(4 * MB);
    // First link works for 1s; every refreshed link is single-use: it
    // answers the refresh probe, then refuses the data request. Refreshes
    // "succeed" but never deliver a byte: must abort, not loop.
    let links = 0;
    const uses = new Map();
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      if (u.pathname === '/release') {
        links++;
        res.writeHead(302, { Location: `/signed?id=${links}&exp=${Date.now() + 1000}` });
        res.end();
        return;
      }
      const id = +u.searchParams.get('id');
      uses.set(id, (uses.get(id) || 0) + 1);
      if (Date.now() > +u.searchParams.get('exp') || (id > 1 && uses.get(id) > 1)) { res.writeHead(403); res.end('expired'); return; }
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      if (b - a < 64 * 1024) { res.end(buf.subarray(a, b + 1)); return; } // probe
      res.write(buf.subarray(a, a + 64 * 1024));
      setTimeout(() => { try { q.socket.destroy(); } catch {} }, 1500);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const t0 = Date.now();
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '2', '--json'], { cwd: work, timeoutMs: 170000 });
      assert.equal(r.code, 1);
      assert.match(r.stdout + r.stderr, /refresh failed repeatedly/);
      assert.ok(Date.now() - t0 < 120000, 'bounded');
    } finally {
      s.close();
    }
  });

  it('single-stream refreshes an expired signed link and resumes (R2)', { timeout: 180000 }, async () => {
    const work = H.workdir('rel-single-refresh');
    const buf = crypto.randomBytes(4 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    // Connection drops at each 1MB mark; by then the 1s link has expired.
    const { s, st } = signedLinkServer(buf, {
      lifeMs: 1000,
      pace: { bytes: 64 * 1024, ms: 100 },
      cutAt: (off) => (off > 0 && off % MB === 0 ? off : null),
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '1', '--json'], { cwd: work, timeoutMs: 170000 });
      assert.equal(r.code, 0, r.stderr.slice(-400));
      assert.equal(H.sha256(out), hash);
      assert.ok(refreshEvents(r) >= 3, `expected >= 3 refreshes, got ${refreshEvents(r)}`);
      assert.ok(st.served < buf.length * 1.5, `resumed, not restarted (${(st.served / MB).toFixed(1)}MB served)`);
    } finally {
      s.close();
    }
  });

  it('single-stream retry budget resets on progress: many drops, --max-retries 2', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-single-retry-reset');
    const buf = crypto.randomBytes(4 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let gets = 0;
    // Every data connection dies after ~512KB: 8 drops, far more than
    // --max-retries 2, but each attempt advances, so it must still finish.
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      if (b - a < 64 * 1024) { res.end(buf.subarray(a, b + 1)); return; } // probe
      gets++;
      const stop = Math.min(b + 1, a + 512 * 1024);
      res.write(buf.subarray(a, stop));
      if (stop > b) res.end(); else setTimeout(() => { try { q.socket.destroy(); } catch {} }, 100);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f.bin`, '-o', out, '-n', '1', '--max-retries', '2', '--json'], { cwd: work });
      assert.equal(r.code, 0, r.stderr.slice(-300));
      assert.equal(H.sha256(out), hash);
      assert.ok(gets >= 8, `expected >= 8 data connections, got ${gets}`);
    } finally {
      s.close();
    }
  });

  it('resuming without any validator warns to use --sha256 (once, silent with ETag)', { timeout: 120000 }, async () => {
    for (const withEtag of [false, true]) {
      const work = H.workdir(`rel-novalidator-${withEtag}`);
      const buf = crypto.randomBytes(6 * MB);
      const s = require('http').createServer((q, res) => {
        const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
        const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
        res.writeHead(m ? 206 : 200, { ...(withEtag ? { ETag: '"v1"' } : {}), 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
        let off = a;
        const tick = () => {
          if (res.destroyed) return;
          const n = Math.min(64 * 1024, b - off + 1);
          res.write(buf.subarray(off, off + n));
          off += n;
          if (off > b) res.end(); else setTimeout(tick, 100);
        };
        tick();
      });
      await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
      try {
        const url = `http://127.0.0.1:${s.address().port}/f.bin`;
        const out = path.join(work, 'o.bin');
        for (const n of ['1', '4']) {
          const c = spawn('node', [H.AGENT_DLA, url, '-o', out, '-n', n], { cwd: work });
          const closed = new Promise((r) => c.on('close', r));
          // Kill only once real progress is on disk (a fixed sleep flakes under load).
          const progressed = () => {
            try {
              if (n === '1') return fs.statSync(out + '.partial').size > 128 * 1024 && fs.existsSync(out + '.single.json');
              const m = JSON.parse(fs.readFileSync(out + '.manifest.json', 'utf8'));
              return (m.done || []).length > 0 || Object.keys(m.active || {}).length > 0;
            } catch { return false; }
          };
          for (let i = 0; i < 300 && !progressed(); i++) await H.sleep(100);
          assert.ok(progressed(), 'first run made progress before the kill');
          c.kill();
          await closed;
          const r = await H.runAccel([url, '-o', out, '-n', n, '--json'], { cwd: work });
          assert.equal(r.code, 0);
          assert.match(r.stderr, /Resuming/, 'second run resumed');
          assert.equal(/no ETag or Last-Modified/.test(r.stderr), !withEtag, `warning iff no validators (etag=${withEtag}, -n ${n})`);
          fs.rmSync(out, { force: true });
          fs.rmSync(path.join(work, '.agent-dla'), { recursive: true, force: true });
        }
      } finally {
        s.close();
      }
    }
  });

  // ---- Codex review findings (round 6) ----
  const rangeHeaders = (buf, q) => {
    const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
    const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
    return { a, b, status: m ? 206 : 200, headers: { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) } };
  };

  it('a refresh in flight is joined, not rejected by the cap (pending fifth refresh)', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-pending-refresh');
    const buf = crypto.randomBytes(4 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let links = 0;
    // Links 1-5 refuse every data request (born bad); link 6 works. Each
    // re-probe is slow, so all four workers pile up while the fifth refresh
    // is pending: they must join it instead of tripping the cap.
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      if (u.pathname === '/release') {
        const go = () => { links++; res.writeHead(302, { Location: `/signed?id=${links}` }); res.end(); };
        if (links === 0) go(); else setTimeout(go, 600);
        return;
      }
      const { a, b, status, headers } = rangeHeaders(buf, q);
      const id = +u.searchParams.get('id');
      if (id < 6 && b - a > 0) { res.writeHead(403); res.end('bad link'); return; }
      res.writeHead(status, headers);
      res.end(buf.subarray(a, b + 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '4', '--json'], { cwd: work, timeoutMs: 100000 });
      assert.equal(r.code, 0, r.stderr.slice(-300) + r.stdout.slice(-300));
      assert.equal(H.sha256(out), hash);
    } finally {
      s.close();
    }
  });

  it('a fresh signed link is used immediately (no 300ms pause before the retry)', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-refresh-immediate');
    const buf = crypto.randomBytes(1 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let links = 0;
    // The first link is dead on arrival; every refreshed link lives 280ms,
    // shorter than the old inter-attempt pause.
    const s = require('http').createServer((q, res) => {
      const u = new URL(q.url, 'http://x');
      if (u.pathname === '/release') {
        links++;
        res.writeHead(302, { Location: `/signed?exp=${links === 1 ? 0 : Date.now() + 280}` });
        res.end();
        return;
      }
      const { a, b, status, headers } = rangeHeaders(buf, q);
      if (b - a > 0 && Date.now() > +u.searchParams.get('exp')) { res.writeHead(403); res.end('expired'); return; }
      res.writeHead(status, headers);
      res.end(buf.subarray(a, b + 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '1', '--json'], { cwd: work, timeoutMs: 50000 });
      assert.equal(r.code, 0, r.stderr.slice(-300) + r.stdout.slice(-300));
      assert.equal(H.sha256(out), hash);
      assert.ok(links <= 3, `single-stream: one refresh should suffice (saw ${links - 1})`);
      // chunked path too: the old 300ms pause burned a refresh per attempt
      const out2 = path.join(work, 'o2.bin');
      links = 0;
      const r2 = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out2, '-n', '2', '--json'], { cwd: work, timeoutMs: 50000 });
      assert.equal(r2.code, 0, r2.stderr.slice(-300) + r2.stdout.slice(-300));
      assert.equal(H.sha256(out2), hash);
      assert.ok(links <= 3, `chunked: one refresh should suffice (saw ${links - 1})`);
    } finally {
      s.close();
    }
  });

  it('a discarded .partial does not freeze the single-stream retry baseline', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-single-baseline');
    const buf = crypto.randomBytes(4 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    const s = require('http').createServer((q, res) => {
      const { a, b, status, headers } = rangeHeaders(buf, q);
      res.writeHead(status, headers);
      if (b - a < 64 * 1024) { res.end(buf.subarray(a, b + 1)); return; } // probe
      const stop = Math.min(b + 1, a + 512 * 1024);
      res.write(buf.subarray(a, stop));
      if (stop > b) res.end(); else setTimeout(() => { try { q.socket.destroy(); } catch {} }, 100);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      // A stranger's full-size .partial (no sidecar): single-stream discards it.
      fs.writeFileSync(out + '.partial', Buffer.alloc(4 * MB));
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f.bin`, '-o', out, '-n', '1', '--max-retries', '2', '--json'], { cwd: work });
      assert.equal(r.code, 0, r.stderr.slice(-300));
      assert.equal(H.sha256(out), hash);
    } finally {
      s.close();
    }
  });

  // The lock code is exercised in-process with fake pids and a hooked fs so
  // the exact interleavings from the review are deterministic.
  function lockHarness(pid, alive, fsHooks = {}) {
    const src = fs.readFileSync(H.AGENT_DLA, 'utf8');
    const from = src.indexOf('const heldLocks = new Set();');
    const to = src.indexOf("process.on('exit', () => { for (const l of heldLocks)");
    assert.ok(from > 0 && to > from, 'lock block located');
    const fakeProcess = { pid, kill: (p) => { if (alive.has(p)) return true; const e = new Error('ESRCH'); e.code = 'ESRCH'; throw e; } };
    const hooked = new Proxy(fs, { get(t, k) { const f = t[k]; return typeof f === 'function' ? (...args) => { if (fsHooks.before) fsHooks.before(k, args); return f.apply(t, args); } : f; } });
    const warnings = [];
    const mod = new Function('fs', 'path', 'process', 'warn', `${src.slice(from, to)}; return { acquireOutputLock, heldLocks };`)(hooked, path, fakeProcess, (m) => warnings.push(m));
    return { ...mod, warnings };
  }

  it('lock file is never visible empty, and stale takeover cannot displace a live lock (N2 races)', () => {
    const work = H.workdir('rel-lock-sim');
    const out = path.join(work, 'o.bin');
    const lockPath = out + '.partial.lock';
    const alive = new Set([111, 222]);

    // 1. Never empty: before every fs call, an existing lock must hold a pid.
    let emptySeen = false;
    const A = lockHarness(111, alive, { before: () => { try { if (fs.readFileSync(lockPath, 'utf8') === '') emptySeen = true; } catch {} } });
    const relA = A.acquireOutputLock(out);
    assert.ok(typeof relA === 'function', 'A holds the lock');
    assert.equal(emptySeen, false, 'lock never observable empty (a racing stale-takeover would delete it)');
    assert.equal(fs.readFileSync(lockPath, 'utf8'), '111');

    // 2. Live holder: a second process refuses.
    const B = lockHarness(222, alive);
    assert.throws(() => B.acquireOutputLock(out), /already writing/);
    assert.equal(fs.readFileSync(lockPath, 'utf8'), '111', 'refusal leaves the live lock alone');

    // 3. Release removes only our own lock.
    fs.writeFileSync(lockPath, '222'); // a successor now owns it
    relA();
    assert.equal(fs.readFileSync(lockPath, 'utf8'), '222', "A's release must not delete B's live lock");
    fs.unlinkSync(lockPath);

    // 4. Takeover race: stale lock (pid 999 dead). Just as C moves it aside,
    // D completes a full takeover and holds a live lock; C must not displace D.
    fs.writeFileSync(lockPath, '999');
    alive.add(333).add(444);
    let D = null;
    const Dh = lockHarness(444, alive);
    let injected = false;
    const C = lockHarness(333, alive, {
      before: (k) => { if (k === 'renameSync' && !injected) { injected = true; D = Dh.acquireOutputLock(out); } },
    });
    assert.throws(() => C.acquireOutputLock(out), /already writing/, 'C must refuse: D took the stale lock first');
    assert.ok(typeof D === 'function', 'D holds the lock');
    assert.equal(fs.readFileSync(lockPath, 'utf8'), '444', "D's live lock intact");
    D();
    assert.ok(!fs.existsSync(lockPath));
    assert.deepEqual(fs.readdirSync(work).filter((f) => /.(tmp|stale)/.test(f)), [], 'no temp/stale leftovers');

    // 5. Garbage/empty locks are stale; an unwritable directory fails open WITH a warning.
    for (const junk of ['', 'garbage', '0', '-1', '3.7']) {
      fs.writeFileSync(lockPath, junk);
      const rel = lockHarness(555, alive).acquireOutputLock(out);
      assert.ok(typeof rel === 'function', `junk lock "${junk}" taken over`);
      rel();
    }
    const W = lockHarness(666, alive, { before: (k, args) => { if (k === 'writeFileSync' && /.tmp$/.test(String(args[0]))) { const e = new Error('no space'); e.code = 'ENOSPC'; throw e; } } });
    assert.equal(W.acquireOutputLock(out), null, 'cannot create a lock: continue unlocked');
    assert.ok(W.warnings.some((m) => /cannot create output lock/.test(m)), 'and say so');
    assert.ok(!fs.existsSync(lockPath), 'no half-created lock left behind');
  });

  it('unknown-size resume restarts instead of accepting a short 206', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-unknown-size');
    const buf = crypto.randomBytes(200 * 1024);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let drops = 0;
    // No Content-Length (chunked, size unknown). First request streams 40KB
    // then dies; a Range request is answered with a truncated 206.
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-/.exec(q.headers.range || '');
      if (m && +m[1] === 0) { res.writeHead(200); res.end(); return; } // probe: nothing useful
      if (m && +m[1] > 0) {
        const a = +m[1];
        res.writeHead(206, { 'Content-Range': `bytes ${a}-${a + 1023}/${buf.length}` });
        res.end(buf.subarray(a, a + 1024)); // truncated tail
        return;
      }
      res.writeHead(200);
      if (drops++ === 0) { res.write(buf.subarray(0, 40 * 1024)); setTimeout(() => { try { q.socket.destroy(); } catch {} }, 100); return; }
      res.end(buf);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const url = `http://127.0.0.1:${s.address().port}/f.bin`;
      const r = await H.runAccel([url, '-o', out, '-n', '1', '--json'], { cwd: work });
      if (r.code === 0) assert.equal(H.sha256(out), hash, 'exit 0 must mean the exact file');
      // Whatever happened, a short file must never be certified.
      if (fs.existsSync(out)) assert.equal(fs.statSync(out).size, buf.length, 'no truncated output published');
    } finally {
      s.close();
    }
  });

  it('server-chosen names that look like staging files are refused', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-staging-names');
    const s = require('http').createServer((q, res) => {
      res.writeHead(200, { 'Content-Length': 5 });
      res.end('hello');
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      for (const name of ['item.partial', 'item.manifest.json', 'item.single.json', 'item.partial.lock']) {
        const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/${name}`, '--json'], { cwd: work });
        assert.equal(r.code, 1, name);
        assert.match(r.stdout + r.stderr, /staging file/);
        assert.ok(!fs.existsSync(path.join(work, name)), `${name} not written`);
      }
      // An explicit -o is the user's choice and still works.
      const r2 = await H.runAccel([`http://127.0.0.1:${s.address().port}/item.partial`, '-o', path.join(work, 'ok.bin'), '--json'], { cwd: work });
      assert.equal(r2.code, 0);
    } finally {
      s.close();
    }
  });

  it('single-stream trickle (bytes per attempt) still exhausts --max-retries', { timeout: 60000 }, async () => {
    const work = H.workdir('rel-single-trickle');
    const buf = crypto.randomBytes(1 * MB);
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      if (b - a < 64 * 1024) { res.end(buf.subarray(a, b + 1)); return; } // probe
      res.write(buf.subarray(a, a + 100)); // 100 bytes, then drop
      setTimeout(() => { try { q.socket.destroy(); } catch {} }, 50);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const t0 = Date.now();
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/f.bin`, '-o', path.join(work, 'o.bin'), '-n', '1', '--max-retries', '2', '--json'], { cwd: work, timeoutMs: 50000 });
      assert.equal(r.code, 1);
      assert.match(r.stdout + r.stderr, /single-stream failed 2x/);
      assert.ok(Date.now() - t0 < 30000, 'bounded');
    } finally {
      s.close();
    }
  });

  it('resume plans no job across bytes the manifest already holds', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-plan-gaps');
    const buf = crypto.randomBytes(24 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    const ranges = [];
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      if (m) ranges.push([a, b]);
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      res.end(buf.subarray(a, b + 1));
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      // Hand-built state: done [4MB,12MB) and [16MB,20MB); everything else missing.
      const url = `http://127.0.0.1:${s.address().port}/f.bin`;
      const first = await H.runAccel([url, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(first.code, 0);
      fs.rmSync(out);
      fs.rmSync(path.join(work, '.agent-dla'), { recursive: true, force: true });
      const partial = Buffer.alloc(24 * MB);
      buf.copy(partial, 4 * MB, 4 * MB, 12 * MB);
      buf.copy(partial, 16 * MB, 16 * MB, 20 * MB);
      fs.writeFileSync(out + '.partial', partial);
      const key = `${new URL(url).origin}/f.bin|${24 * MB}||`;
      fs.writeFileSync(out + '.manifest.json', JSON.stringify({ key, done: [[4 * MB, 12 * MB - 1], [16 * MB, 20 * MB - 1]], active: {} }));
      ranges.length = 0;
      const r = await H.runAccel([url, '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0, r.stderr.slice(-300));
      assert.equal(H.sha256(out), hash);
      const inDone = (a, b) => [[4 * MB, 12 * MB - 1], [16 * MB, 20 * MB - 1]].some(([s0, e0]) => a <= e0 && b >= s0);
      for (const [a, b] of ranges) {
        if (a === 0 && b === 0) continue; // probe
        assert.ok(!inDone(a, b), `job [${a}, ${b}] overlaps bytes already in the manifest`);
      }
    } finally {
      s.close();
    }
  });

  it('a second run into the same output refuses; stale locks are taken over (N2)', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-output-lock');
    const buf = crypto.randomBytes(4 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, b - off + 1);
        res.write(buf.subarray(off, off + n));
        off += n;
        if (off > b) res.end(); else setTimeout(tick, 100);
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const url = `http://127.0.0.1:${s.address().port}/f.bin`;
      const out = path.join(work, 'o.bin');
      const first = spawn('node', [H.AGENT_DLA, url, '-o', out, '-n', '1'], { cwd: work });
      const firstDone = new Promise((r) => first.on('close', r));
      await H.sleep(1500);
      assert.ok(fs.existsSync(out + '.partial.lock'), 'lock held while downloading');
      const r2 = await H.runAccel([url, '-o', out, '-n', '1', '--json'], { cwd: work });
      assert.equal(r2.code, 1, 'second run must refuse, not share the .partial');
      assert.match(r2.stdout + r2.stderr, /already writing/);
      assert.equal(await firstDone, 0);
      assert.equal(H.sha256(out), hash, 'first run finished with exact bytes');
      assert.ok(!fs.existsSync(out + '.partial.lock'), 'lock released on completion');
      // A lock left by a killed process (dead pid) is stale: taken over.
      fs.rmSync(out);
      fs.rmSync(path.join(work, '.agent-dla'), { recursive: true, force: true });
      fs.writeFileSync(out + '.partial.lock', '2147483000'); // no such pid
      const r3 = await H.runAccel([url, '-o', out, '-n', '1', '--json'], { cwd: work });
      assert.equal(r3.code, 0, r3.stderr.slice(-300));
      assert.equal(H.sha256(out), hash);
      assert.ok(!fs.existsSync(out + '.partial.lock'), 'stale lock replaced then released');
    } finally {
      s.close();
    }
  });

  it('single-stream revoked link aborts fast with progress kept (R2)', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-single-revoked');
    const buf = crypto.randomBytes(4 * MB);
    // After the first link, the origin refuses for good (revoked).
    const { s } = signedLinkServer(buf, {
      lifeMs: 1000,
      pace: { bytes: 64 * 1024, ms: 100 },
      cutAt: (off) => (off >= MB ? 'once' : null),
      release: (n) => (n > 1 ? 403 : null),
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const t0 = Date.now();
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '1', '--json'], { cwd: work, timeoutMs: 110000 });
      assert.equal(r.code, 1);
      assert.match(r.stdout + r.stderr, /revoked|HTTP 403/);
      assert.ok(Date.now() - t0 < 30000, `aborted fast (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
      assert.ok(fs.existsSync(out + '.partial'), 'progress kept for a rerun');
    } finally {
      s.close();
    }
  });

  it('origin outage during refresh recovers', { timeout: 120000 }, async () => {
    const work = H.workdir('rel-outage');
    const buf = crypto.randomBytes(4 * MB);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    const t0 = Date.now();
    const outageUntil = t0 + 6000;
    let dropped = false;
    const s = require('http').createServer((q, res) => {
      if (Date.now() < outageUntil && q.url !== '/release-probe-ok') {
        // total outage: kill everything (but let the first probe through below)
      }
      const u = new URL(q.url, 'http://x');
      if (u.pathname === '/release') {
        if (Date.now() < outageUntil && Date.now() - t0 > 300) { try { q.socket.destroy(); } catch {} return; }
        res.writeHead(302, { Location: `/signed?exp=${Date.now() + 1200}` });
        res.end();
        return;
      }
      if (Date.now() < outageUntil) { try { q.socket.destroy(); } catch {} return; }
      if (Date.now() > +u.searchParams.get('exp')) { res.writeHead(403); res.end('expired'); return; }
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0, b = m && m[2] ? +m[2] : buf.length - 1;
      res.writeHead(m ? 206 : 200, { 'Content-Length': b - a + 1, ETag: '"stable"', ...(m ? { 'Content-Range': `bytes ${a}-${b}/${buf.length}` } : {}) });
      if (a === 2 * MB && !dropped) {
        dropped = true;
        res.write(buf.subarray(a, a + 1000));
        setTimeout(() => { try { q.socket.destroy(); } catch {} }, 500);
        return;
      }
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, b - off + 1);
        res.write(buf.subarray(off, off + n));
        off += n;
        if (off > b) res.end();
        else setTimeout(tick, 120); // ~500KB/s: attempts span the outage
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'o.bin');
      const t1 = Date.now();
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/release`, '-o', out, '-n', '4', '--json'], { cwd: work });
      const secs = (Date.now() - t1) / 1000;
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), hash);
      assert.ok(secs < 60, `recovered after outage (took ${secs.toFixed(1)}s)`);
    } finally {
      s.close();
    }
  });
});
