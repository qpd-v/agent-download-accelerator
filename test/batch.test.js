const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const H = require('./helpers');

describe('batch and config', () => {
  it('list downloads all files, honors agent-dla.json, reruns cached', { timeout: 180000 }, async () => {
    const work = H.workdir('batch-ok');
    const fa = H.makeFile(work, 'srcA.bin', 2 * 1024 * 1024, 7);
    const fb = H.makeFile(work, 'srcB.bin', 3 * 1024 * 1024, 13);
    const srv = await H.startServer({
      '/a.bin': { buf: fs.readFileSync(fa.path), tmp: path.join(work, 'srvA.tmp') },
      '/b.bin': { buf: fs.readFileSync(fb.path), tmp: path.join(work, 'srvB.tmp') },
    });
    try {
      fs.writeFileSync(path.join(work, 'agent-dla.json'), JSON.stringify({ connections: 2 }));
      fs.writeFileSync(path.join(work, 'urls.txt'), `# batch\n${srv.url('/a.bin')}\n\n${srv.url('/b.bin')}\n`);
      let r = await H.runAccel(['--list', path.join(work, 'urls.txt'), '--json'], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(path.join(work, 'a.bin')), fa.hash);
      assert.equal(H.sha256(path.join(work, 'b.bin')), fb.hash);
      let ev = H.events(r.stdout);
      assert.ok(ev.filter((e) => e.event === 'start').every((e) => e.connections === 2));
      const bd = ev.find((e) => e.event === 'batch-done');
      assert.ok(bd && bd.completed === 2 && bd.bytes === 5 * 1024 * 1024);
      r = await H.runAccel(['--list', path.join(work, 'urls.txt'), '--json'], { cwd: work });
      assert.equal(r.code, 0);
      ev = H.events(r.stdout);
      assert.equal(ev.filter((e) => e.event === 'done' && e.cached === true).length, 2);
    } finally {
      await srv.close();
    }
  });

  it('ambiguous batch combos exit 2; bad file does not stop batch', { timeout: 180000 }, async () => {
    const work = H.workdir('batch-mixed');
    const fa = H.makeFile(work, 'srcA.bin', 2 * 1024 * 1024, 7);
    const srv = await H.startServer({ '/a.bin': { buf: fs.readFileSync(fa.path), tmp: path.join(work, 'srvA.tmp') } });
    try {
      fs.writeFileSync(path.join(work, 'urls.txt'), `${srv.url('/a.bin')}\n`);
      fs.writeFileSync(path.join(work, 'urls2.txt'), `${srv.url('/a.bin')}\n${srv.url('/gone')}\n`);
      let r = await H.runAccel(['--list', path.join(work, 'urls2.txt'), '--mirror', srv.url('/a.bin')], { cwd: work });
      assert.equal(r.code, 2);
      r = await H.runAccel(['--list', path.join(work, 'urls2.txt'), '-o', path.join(work, 'x.bin')], { cwd: work });
      assert.equal(r.code, 2);
      fs.writeFileSync(path.join(work, 'mixed.txt'), `${srv.url('/gone')}\n${srv.url('/a.bin')}\n`);
      try { fs.unlinkSync(path.join(work, 'a.bin')); } catch {}
      r = await H.runAccel(['--list', path.join(work, 'mixed.txt'), '--json'], { cwd: work });
      assert.equal(r.code, 1);
      assert.equal(H.sha256(path.join(work, 'a.bin')), fa.hash);
      assert.ok(H.events(r.stdout).some((e) => e.event === 'error' && e.scope === 'file'));
    } finally {
      await srv.close();
    }
  });

  it('--dir collects outputs', { timeout: 120000 }, async () => {
    const work = H.workdir('batch-dir');
    const fb = H.makeFile(work, 'srcB.bin', 2 * 1024 * 1024, 13);
    const srv = await H.startServer({ '/b.bin': { buf: fs.readFileSync(fb.path), tmp: path.join(work, 'srvB.tmp') } });
    try {
      const r = await H.runAccel([srv.url('/b.bin'), '--dir', path.join(work, 'dl')], { cwd: work });
      assert.equal(r.code, 0);
      assert.equal(H.sha256(path.join(work, 'dl', 'b.bin')), fb.hash);
    } finally {
      await srv.close();
    }
  });
});
