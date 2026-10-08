const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const H = require('./helpers');

const BADHASH = '0'.repeat(64);

describe('version', () => {
  it('--version / -V print the package version and exit 0', async () => {
    const pkg = require('../package.json');
    for (const flag of ['--version', '-V']) {
      const r = await H.runAccel([flag]);
      assert.equal(r.code, 0);
      assert.equal(r.stdout.trim(), pkg.version);
    }
  });
});

describe('guards', () => {
  it('sha256/expect-size/expect-type pass, hash in done event', { timeout: 120000 }, async () => {
    const work = H.workdir('guards-ok');
    const src = H.makeFile(work, 'src.bin', 4 * 1024 * 1024, 29);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp'), type: 'application/octet-stream' } });
    try {
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '4', '--json', '--sha256', src.hash, '--expect-size', '4MB', '--expect-type', 'application/octet-stream'], { cwd: work });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      assert.equal(ev.find((e) => e.event === 'done').sha256, src.hash);
    } finally {
      await srv.close();
    }
  });

  it('wrong sha256 exits 1 and deletes output', { timeout: 120000 }, async () => {
    const work = H.workdir('guards-sha');
    const src = H.makeFile(work, 'src.bin', 4 * 1024 * 1024, 29);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '4', '--json', '--sha256', BADHASH], { cwd: work });
      assert.equal(r.code, 1);
      assert.ok(!fs.existsSync(out) && !fs.existsSync(out + '.partial'));
      assert.ok(H.events(r.stdout).some((e) => e.event === 'error' && e.scope === 'verify'));
    } finally {
      await srv.close();
    }
  });

  it('wrong expect-size / max-size / expect-type fail fast', { timeout: 120000 }, async () => {
    const work = H.workdir('guards-fast');
    const src = H.makeFile(work, 'src.bin', 4 * 1024 * 1024, 29);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp'), type: 'application/octet-stream' } });
    try {
      let r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'a.bin'), '--expect-size', '5MB', '--json'], { cwd: work });
      assert.equal(r.code, 1);
      assert.ok(!fs.existsSync(path.join(work, 'a.bin')));
      r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'b.bin'), '--max-size', '1MB', '--json'], { cwd: work });
      assert.equal(r.code, 1);
      assert.ok(!fs.existsSync(path.join(work, 'b.bin')));
      r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'c.bin'), '--expect-type', 'video/mp4', '--json'], { cwd: work });
      assert.equal(r.code, 1);
      assert.ok(!fs.existsSync(path.join(work, 'c.bin')));
      r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'd.bin'), '--sha256', 'xyz'], { cwd: work });
      assert.equal(r.code, 2);
    } finally {
      await srv.close();
    }
  });

  it('html responses are refused, not saved', { timeout: 60000 }, async () => {
    const work = H.workdir('guards-html');
    const s = require('http').createServer((q, res) => {
      const html = '<html><body>login required</body></html>';
      res.writeHead(200, { 'Content-Type': 'text/html', 'Content-Length': Buffer.byteLength(html) });
      res.end(html);
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const out = path.join(work, 'file.zip');
      const r = await H.runAccel([`http://127.0.0.1:${s.address().port}/file.zip`, '-o', out, '--json'], { cwd: work });
      assert.equal(r.code, 1);
      assert.match(r.stdout + r.stderr, /text\/html/);
      assert.ok(!fs.existsSync(out));
    } finally {
      s.close();
    }
  });

  it('max-size aborts mid-stream on unknown size', { timeout: 120000 }, async () => {
    const work = H.workdir('guards-mid');
    const src = H.makeFile(work, 'src.bin', 4 * 1024 * 1024, 29);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    // chunked-encoding endpoint: no length, ignores Range
    const srv2 = await httpStreamServer(work);
    try {
      const t0 = Date.now();
      const r = await H.runAccel([srv2.url('/stream'), '-o', path.join(work, 'out.bin'), '--max-size', '100KB', '--json'], { cwd: work });
      assert.equal(r.code, 1);
      assert.ok(Date.now() - t0 < 60000, 'no retry storm');
      assert.ok(/max-size/.test(r.stdout + r.stderr));
    } finally {
      await srv.close();
      await srv2.close();
    }
  });
});

function httpStreamServer(work) {
  const http = require('http');
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
    fs.createReadStream(path.join(work, 'src.bin')).pipe(res);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({
      url: (p) => `http://127.0.0.1:${server.address().port}${p}`,
      close: () => new Promise((r) => server.close(r)),
    }));
  });
}
