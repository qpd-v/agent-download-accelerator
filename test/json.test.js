const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const H = require('./helpers');

describe('json mode', () => {
  it('chunked run is pure NDJSON with full event sequence', { timeout: 120000 }, async () => {
    const work = H.workdir('json-chunked');
    const src = H.makeFile(work, 'src.bin', 8 * 1024 * 1024, 17);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '4', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout); // throws on any non-JSON line
      assert.ok(ev.length > 0);
      assert.equal(ev[0].event, 'batch');
      const start = ev.find((e) => e.event === 'start');
      assert.equal(start.size, src.size);
      assert.ok(ev.some((e) => e.event === 'progress' && typeof e.bytes_done === 'number'));
      assert.equal(ev.filter((e) => e.event === 'chunk-done').length, 4);
      const done = ev.find((e) => e.event === 'done');
      assert.equal(done.event, 'done');
      assert.equal(done.bytes, src.size);
      assert.match(r.stderr, /Size:/);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('single-stream run emits start/progress/done', { timeout: 120000 }, async () => {
    const work = H.workdir('json-single');
    const src = H.makeFile(work, 'src.bin', 8 * 1024 * 1024, 17);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '1', '--json'], { cwd: work });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      assert.equal(ev[0].event, 'batch');
      assert.ok(ev.some((e) => e.event === 'start'));
      assert.ok(ev.some((e) => e.event === 'progress'));
      assert.equal(ev.find((e) => e.event === 'done').bytes, src.size);
      assert.equal(H.sha256(out), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('human mode has no JSON events', { timeout: 120000 }, async () => {
    const work = H.workdir('json-human');
    const src = H.makeFile(work, 'src.bin', 2 * 1024 * 1024, 17);
    const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
    try {
      const out = path.join(work, 'out.bin');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', out, '-n', '2'], { cwd: work });
      assert.equal(r.code, 0);
      assert.ok(!/"event"/.test(r.stdout));
      assert.match(r.stdout + r.stderr, /Saved ->/);
    } finally {
      await srv.close();
    }
  });
});
