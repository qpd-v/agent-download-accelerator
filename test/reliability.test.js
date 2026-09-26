const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { spawn } = require('child_process');
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
    const buf = Buffer.alloc(8 * MB, 7);
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
      assert.equal(H.sha256(out), require('crypto').createHash('sha256').update(buf).digest('hex'));
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
    const src = H.makeFile(work, 'src.bin', 40 * MB);
    const buf = fs.readFileSync(src.path);
    const srv = await H.startServer({ '/f.bin': { buf, tmp: path.join(work, 'srv.tmp') } }, () => ({ slowBps: 2 * MB }));
    try {
      const out = path.join(work, 'o.bin');
      const c = spawn('node', [H.AGENT_DLA, srv.url('/f.bin'), '-o', out, '-n', '4'], { cwd: work });
      await H.sleep(4500);
      c.kill();
      await new Promise((r) => c.on('close', r));
      assert.ok(fs.existsSync(out + '.partial'), 'partial kept after kill');
      const m = JSON.parse(fs.readFileSync(out + '.manifest.json', 'utf8'));
      const kept = (m.done || []).reduce((t, [s, e]) => t + (e - s + 1), 0)
        + Object.values(m.active || {}).reduce((t, [s, x]) => t + Math.max(0, x - s), 0);
      assert.ok(kept > 0, 'manifest records transferred bytes');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
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
    const big = Buffer.alloc(8 * MB, 1);
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
      assert.equal(H.sha256(out), require('crypto').createHash('sha256').update(big).digest('hex'));
    } finally {
      s.close();
    }
  });
});
