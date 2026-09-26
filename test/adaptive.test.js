const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const H = require('./helpers');

const FAST_ENV = { AGENT_DLA_SPLIT_STALL_S: '5', AGENT_DLA_SPLIT_COOLDOWN_S: '5' };

describe('adaptive', () => {
  it('stalled chunk is split and download completes', { timeout: 240000 }, async () => {
    const work = H.workdir('adaptive-split');
    const src = H.makeFile(work, 'src.bin', 16 * 1024 * 1024, 31);
    const srv = await H.startServer(
      { '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } },
      (req, { start }) => ((start >= 8 * 1024 * 1024 && start < 12 * 1024 * 1024) ? { slowBps: 50 * 1024 } : null),
    );
    try {
      const out = path.join(work, 'out.bin');
      const t0 = Date.now();
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work, env: FAST_ENV, timeoutMs: 200000 });
      const secs = (Date.now() - t0) / 1000;
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      assert.ok(ev.filter((e) => e.event === 'split').length >= 1, 'splits happened');
      assert.equal(H.sha256(out), src.hash);
      assert.ok(secs < 120, `split path ${secs.toFixed(0)}s beats unsplit ~80s+`);
      console.log(`    split wall: ${secs.toFixed(0)}s`);
    } finally {
      await srv.close();
    }
  });
});
