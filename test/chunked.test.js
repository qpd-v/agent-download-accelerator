const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const H = require('./helpers');

describe('chunked download', () => {
  it('downloads multi-connection byte-identical with correct events', { timeout: 120000 }, async () => {
    const work = H.workdir('chunked');
    const src = H.makeFile(work, 'src.bin', 8 * 1024 * 1024, 7);
    const srv2 = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      const r = await H.runAccel([srv2.url('/f.bin'), '-o', path.join(work, 'out.bin'), '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      assert.equal(ev[0].event, 'batch');
      const start = ev.find((e) => e.event === 'start');
      assert.equal(start.size, src.size);
      assert.equal(start.connections, 4);
      assert.equal(ev.filter((e) => e.event === 'chunk-done').length, 4);
      const done = ev.find((e) => e.event === 'done');
      assert.equal(done.event, 'done');
      assert.equal(done.bytes, src.size);
      assert.equal(H.sha256(path.join(work, 'out.bin')), src.hash);
    } finally {
      await srv2.close();
    }
  });
});
