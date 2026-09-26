const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const http = require('http');
const H = require('./helpers');

// Minimal HTTP forward proxy (absolute-form requests, http only) for tests.
function startForwardProxy() {
  const server = http.createServer((clientReq, clientRes) => {
    let target;
    try { target = new URL(clientReq.url); } catch { clientRes.writeHead(400); clientRes.end(); return; }
    if (target.protocol !== 'http:') { clientRes.writeHead(502); clientRes.end(); return; }
    const headers = { ...clientReq.headers };
    delete headers['proxy-authorization'];
    delete headers['proxy-connection'];
    headers.host = target.host;
    const preq = http.request(
      { host: target.hostname, port: target.port || 80, path: target.pathname + target.search, method: clientReq.method, headers },
      (pres) => { clientRes.writeHead(pres.statusCode, pres.headers); pres.pipe(clientRes); },
    );
    preq.on('error', () => { try { clientRes.writeHead(502); clientRes.end(); } catch {} });
    clientReq.pipe(preq);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    server,
    port: server.address().port,
    close: () => new Promise((r) => server.close(r)),
  })));
}

describe('security', () => {
  it('--help exits 0 without touching the network', { timeout: 60000 }, async () => {
    const work = H.workdir('sec-help');
    const r = await H.runAccel(['--help'], { cwd: work });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /Usage:/);
  });

  it('--json --help exits 0 with pure (empty) stdout', { timeout: 60000 }, async () => {
    const work = H.workdir('sec-help-json');
    const r = await H.runAccel(['--help', '--json'], { cwd: work });
    assert.equal(r.code, 0);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /Usage:/);
  });

  it('invalid single URL fails fast with exit 2', { timeout: 60000 }, async () => {
    const work = H.workdir('sec-badurl');
    const t0 = Date.now();
    const r = await H.runAccel(['notaurl', '-o', path.join(work, 'out.bin')], { cwd: work });
    assert.equal(r.code, 2);
    assert.ok(Date.now() - t0 < 15000);
    assert.match(r.stderr, /invalid URL/);
  });

  it('garbage --list lines are skipped fast, good files still complete', { timeout: 120000 }, async () => {
    const work = H.workdir('sec-badlist');
    const src = H.makeFile(work, 'src.bin', 1 * 1024 * 1024, 7);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      fs.writeFileSync(path.join(work, 'urls.txt'), `notaurl\nftp://x/y\n${srv.url('/f.bin')}\n`);
      const t0 = Date.now();
      const r = await H.runAccel(['--list', path.join(work, 'urls.txt'), '--json'], { cwd: work });
      assert.ok(Date.now() - t0 < 60000);
      assert.equal(r.code, 1);
      const ev = H.events(r.stdout);
      assert.equal(ev.filter((e) => e.event === 'error' && e.scope === 'file').length, 2);
      assert.equal(ev.find((e) => e.event === 'batch-done').completed, 1);
      assert.equal(H.sha256(path.join(work, 'f.bin')), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('redirect loop aborts fast instead of retrying', { timeout: 60000 }, async () => {
    const work = H.workdir('sec-redir');
    const src = H.makeFile(work, 'src.bin', 64 * 1024, 7);
    const srv = await H.startServer(
      { '/loop.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } },
      () => ({ status: 302, headers: { location: '/loop.bin' }, body: '' }),
    );
    try {
      const t0 = Date.now();
      const r = await H.runAccel([srv.url('/loop.bin'), '-o', path.join(work, 'out.bin'), '--json'], { cwd: work });
      assert.ok(Date.now() - t0 < 30000);
      assert.equal(r.code, 1);
      assert.match(r.stdout + r.stderr, /too many redirects/);
    } finally {
      await srv.close();
    }
  });

  it('server filename colliding with a tool file is refused', { timeout: 60000 }, async () => {
    const work = H.workdir('sec-clobber');
    const hookSrv = await H.startServer(
      { '/f.bin': { buf: Buffer.from('0123456789'), tmp: path.join(work, 'srv.tmp') } },
      () => ({ status: 200, headers: { 'content-length': '10', 'content-disposition': 'attachment; filename="proxies.txt"' }, body: '0123456789' }),
    );
    try {
      const r = await H.runAccel([hookSrv.url('/f.bin'), '--json'], { cwd: work });
      assert.equal(r.code, 1);
      assert.match(r.stdout + r.stderr, /collides with a tool file/);
      assert.ok(!fs.existsSync(path.join(work, 'proxies.txt')));
    } finally {
      await hookSrv.close();
    }
  });

  it('proxy credentials never appear in events or logs', { timeout: 120000 }, async () => {
    const work = H.workdir('sec-redact');
    const src = H.makeFile(work, 'src.bin', 1 * 1024 * 1024, 7);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    const proxy = await startForwardProxy();
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), `http://user:s3cret@127.0.0.1:${proxy.port}\n`);
      const backstop = path.join(work, 'backstop.js');
      fs.writeFileSync(backstop, 'process.exit(1);\n'); // must never run: list is healthy
      const r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'out.bin'), '-n', '2', '--json'], {
        cwd: work,
        env: { AGENT_DLA_HARVEST_SCRIPT: backstop, AGENT_DLA_HARVEST_TIMEOUT_MS: '10000' },
      });
      assert.equal(r.code, 0);
      assert.ok(!r.stdout.includes('s3cret'), 'secret in stdout');
      assert.ok(!r.stderr.includes('s3cret'), 'secret in stderr');
      const ev = H.events(r.stdout);
      const kept = ev.find((e) => e.event === 'proxies').kept;
      assert.deepEqual(kept, [`http://127.0.0.1:${proxy.port}`]);
      for (const cd of ev.filter((e) => e.event === 'chunk-done')) {
        assert.ok(!String(cd.via || '').includes('@'), `creds in via: ${cd.via}`);
      }
      // JSON event URLs carry no query/fragment
      const start = ev.find((e) => e.event === 'start');
      assert.ok(!start.url.includes('?') && !start.url.includes('#'));
      assert.equal(H.sha256(path.join(work, 'out.bin')), src.hash);
    } finally {
      await srv.close();
      await proxy.close();
    }
  });
});
