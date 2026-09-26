const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const H = require('./helpers');

describe('retries and error classes', () => {
  it('chaos kills are absorbed, result byte-identical', { timeout: 180000 }, async () => {
    const work = H.workdir('retry-chaos');
    const src = H.makeFile(work, 'src.bin', 12 * 1024 * 1024, 11);
    const srv = await H.startServer(
      { '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } },
      (req, { start, end, key, count }) => ((end - start > 100 && count <= 5) ? 'kill' : null),
    );
    try {
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      assert.ok(ev.filter((e) => e.event === 'retry').length >= 4);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('404 aborts fast with no output', { timeout: 60000 }, async () => {
    const work = H.workdir('retry-404');
    const srv = await H.startServer({});
    try {
      const t0 = Date.now();
      const r = await H.runAccel([srv.url('/gone'), '-o', path.join(work, 'out.bin'), '--json'], { cwd: work });
      assert.equal(r.code, 1);
      assert.ok(Date.now() - t0 < 30000);
      assert.ok(/404/.test(r.stdout + r.stderr));
      assert.ok(!fs.existsSync(path.join(work, 'out.bin')));
    } finally {
      await srv.close();
    }
  });

  it('429 honors Retry-After and completes', { timeout: 120000 }, async () => {
    const work = H.workdir('retry-429');
    const src = H.makeFile(work, 'src.bin', 4 * 1024 * 1024, 9);
    const srv = await H.startServer(
      { '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } },
      (req, { key, count }) => (count <= 2 ? { status: 429, headers: { 'Retry-After': '1' }, body: 'slow' } : null),
    );
    try {
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.ok(/throttled/i.test(r.stderr));
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
    }
  });
});
