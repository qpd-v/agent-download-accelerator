const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const H = require('./helpers');

describe('resume', () => {
  it('kill mid-download then rerun completes byte-identical', { timeout: 180000 }, async () => {
    const work = H.workdir('resume');
    const src = H.makeFile(work, 'src.bin', 12 * 1024 * 1024, 11);
    const srv2 = await H.startServer(
      { '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } },
      () => ({ slowBps: 2 * 1024 * 1024 }), // throttle so the kill lands mid-download
    );
    try {
      const out = path.join(work, 'out.bin');
      const child = spawn('node', [H.AGENT_DLA, srv2.url('/f.bin'), '-o', out, '-n', '4'], { cwd: work });
      await H.sleep(2500);
      child.kill(); // hard kill: no handlers run (Windows TerminateProcess)
      await new Promise((r) => child.on('close', r));
      const parts = path.join(work, 'out.bin.parts');
      assert.ok(fs.existsSync(parts), 'parts dir kept after kill');
      const r = await H.runAccel([srv2.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv2.close();
    }
  });

  it('rerun with different -n after partial parts stays byte-identical', { timeout: 180000 }, async () => {
    const work = H.workdir('resume-layout');
    const src = H.makeFile(work, 'src.bin', 12 * 1024 * 1024, 5);
    const srv = await H.startServer(
      { '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } },
      () => ({ slowBps: 2 * 1024 * 1024 }),
    );
    try {
      const out = path.join(work, 'out.bin');
      const child = spawn('node', [H.AGENT_DLA, srv.url('/f.bin'), '-o', out, '-n', '4'], { cwd: work });
      await H.sleep(2500);
      child.kill();
      await new Promise((r) => child.on('close', r));
      assert.ok(fs.existsSync(out + '.parts'), 'parts kept');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('completed file is skipped as cached', { timeout: 120000 }, async () => {
    const work = H.workdir('resume-cached');
    const src = H.makeFile(work, 'src.bin', 2 * 1024 * 1024, 3);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      const out = path.join(work, 'out.bin');
      let r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      assert.ok(ev.some((e) => e.event === 'done' && e.cached === true));
    } finally {
      await srv.close();
    }
  });
});
