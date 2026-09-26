const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const H = require('./helpers');

describe('resume', () => {
  it('kill mid-download then rerun completes byte-identical', { timeout: 180000 }, async () => {
    const work = H.workdir('resume');
    const src = H.makeFile(work, 'src.bin', 40 * 1024 * 1024);
    const srv2 = await H.startServer(
      { '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } },
      () => ({ slowBps: 2 * 1024 * 1024 }), // throttle so the kill lands mid-download
    );
    try {
      const out = path.join(work, 'out.bin');
      const child = spawn('node', [H.AGENT_DLA, srv2.url('/f.bin'), '-o', out, '-n', '4'], { cwd: work });
      const closed = new Promise((r) => child.on('close', r));
      await H.sleep(4000); // 10MB chunks at ~2MB/s: mid-flight
      child.kill(); // hard kill: no handlers run (Windows TerminateProcess)
      await closed;
      const parts = path.join(work, 'out.bin.partial');
      const manifest = path.join(work, 'out.bin.manifest.json');
      assert.ok(fs.existsSync(parts), 'partial kept after kill');
      assert.ok(fs.existsSync(manifest), 'manifest kept after kill');
      const r = await H.runAccel([srv2.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv2.close();
    }
  });

  it('rerun with different -n after partial parts stays byte-identical', { timeout: 180000 }, async () => {
    const work = H.workdir('resume-layout');
    const src = H.makeFile(work, 'src.bin', 40 * 1024 * 1024);
    const srv = await H.startServer(
      { '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } },
      () => ({ slowBps: 2 * 1024 * 1024 }),
    );
    try {
      const out = path.join(work, 'out.bin');
      const child = spawn('node', [H.AGENT_DLA, srv.url('/f.bin'), '-o', out, '-n', '4'], { cwd: work });
      const closed = new Promise((r) => child.on('close', r));
      await H.sleep(4000); // 10MB chunks at ~2MB/s: mid-flight

      child.kill();
      await closed;
      assert.ok(fs.existsSync(out + '.partial'), 'partial kept');
      assert.ok(fs.existsSync(out + '.manifest.json'), 'manifest kept');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('single-stream kill then rerun resumes from the sidecar', { timeout: 180000 }, async () => {
    const work = H.workdir('resume-single');
    const crypto = require('crypto');
    const buf = crypto.randomBytes(12 * 1024 * 1024);
    const hash = crypto.createHash('sha256').update(buf).digest('hex');
    let served = 0;
    const s = require('http').createServer((q, res) => {
      const m = /bytes=(\d+)-(\d*)/.exec(q.headers.range || '');
      const a = m ? +m[1] : 0;
      res.writeHead(m ? 206 : 200, {
        'Content-Length': buf.length - a,
        ...(m ? { 'Content-Range': `bytes ${a}-${buf.length - 1}/${buf.length}` } : {}),
      });
      let off = a;
      const tick = () => {
        if (res.destroyed) return;
        const n = Math.min(64 * 1024, buf.length - off);
        served += n;
        res.write(buf.subarray(off, off + n));
        off += n;
        if (off >= buf.length) res.end();
        else setTimeout(tick, 30); // ~2MB/s
      };
      tick();
    });
    await new Promise((ok) => s.listen(0, '127.0.0.1', ok));
    try {
      const fileUrl = `http://127.0.0.1:${s.address().port}/f.bin`;
      const out = path.join(work, 'out.bin');
      const child = spawn('node', [H.AGENT_DLA, fileUrl, '-o', out, '-n', '1'], { cwd: work });
      const closed = new Promise((r) => child.on('close', r));
      await H.sleep(2500);
      child.kill();
      await closed;
      assert.ok(fs.existsSync(out + '.single.json'), 'sidecar kept after kill');
      const kept = fs.existsSync(out + '.partial') ? fs.statSync(out + '.partial').size : 0;
      assert.ok(kept > 0, 'partial bytes kept after kill');
      served = 0;
      const r = await H.runAccel([fileUrl, '-o', out, '-n', '1', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(out), hash);
      assert.ok(served < buf.length - kept / 2, `rerun resumed (${(served / 1048576).toFixed(1)}MB re-transferred of 12MB, kept ${(kept / 1048576).toFixed(1)}MB)`);
    } finally {
      s.close();
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
