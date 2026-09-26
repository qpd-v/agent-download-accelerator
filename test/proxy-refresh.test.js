const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const H = require('./helpers');

function fakeHarvest(work, name, body) {
  const p = path.join(work, name);
  fs.writeFileSync(p, `const fs = require('fs');\nfs.writeFileSync(process.argv[2], ${JSON.stringify(body)});\n`);
  return p;
}

async function setupFile(work, tag, size = 2 * 1024 * 1024) {
  const src = H.makeFile(work, 'src.bin', size, 7);
  const srv = await H.startServer({ '/f.bin': { buf: fs.readFileSync(src.path), tmp: path.join(work, 'srv.tmp') } });
  return { src, srv };
}

describe('proxy auto-refresh', () => {
  it('all-dead list triggers one harvest, then completes direct', { timeout: 120000 }, async () => {
    const work = H.workdir('proxy-refresh-dead');
    const { src, srv } = await setupFile(work);
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), 'http://127.0.0.1:1\nhttp://127.0.0.1:2\n');
      const fake = fakeHarvest(work, 'fake-harvest.js', '# refreshed by harvest\nhttp://127.0.0.1:1\n');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'out.bin'), '-n', '2', '--json'], {
        cwd: work,
        env: { AGENT_DLA_HARVEST_SCRIPT: fake, AGENT_DLA_HARVEST_TIMEOUT_MS: '30000' },
      });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      const starts = ev.filter((e) => e.event === 'proxies-refresh' && e.phase === 'start');
      const dones = ev.filter((e) => e.event === 'proxies-refresh' && e.phase === 'done');
      assert.equal(starts.length, 1);
      assert.equal(starts[0].reason, 'all-dead');
      assert.equal(dones.length, 1);
      assert.equal(dones[0].ok, true);
      assert.ok(fs.readFileSync(path.join(work, 'proxies.txt'), 'utf8').includes('# refreshed by harvest'));
      assert.equal(ev.find((e) => e.event === 'done').bytes, src.size);
      assert.equal(H.sha256(path.join(work, 'out.bin')), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('empty list triggers harvest with reason empty', { timeout: 120000 }, async () => {
    const work = H.workdir('proxy-refresh-empty');
    const { src, srv } = await setupFile(work);
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), '# nothing here yet\n\n');
      const fake = fakeHarvest(work, 'fake-harvest.js', '# refreshed by harvest\n');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'out.bin'), '-n', '2', '--json'], {
        cwd: work,
        env: { AGENT_DLA_HARVEST_SCRIPT: fake, AGENT_DLA_HARVEST_TIMEOUT_MS: '30000' },
      });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      const starts = ev.filter((e) => e.event === 'proxies-refresh' && e.phase === 'start');
      assert.equal(starts.length, 1);
      assert.equal(starts[0].reason, 'empty');
      assert.ok(fs.readFileSync(path.join(work, 'proxies.txt'), 'utf8').includes('# refreshed by harvest'));
      assert.equal(H.sha256(path.join(work, 'out.bin')), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('--no-auto-refresh skips harvest and completes direct', { timeout: 120000 }, async () => {
    const work = H.workdir('proxy-refresh-optout');
    const { src, srv } = await setupFile(work);
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), 'http://127.0.0.1:1\n');
      const fake = fakeHarvest(work, 'fake-harvest.js', '# must not appear\n');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'out.bin'), '-n', '2', '--json', '--no-auto-refresh'], {
        cwd: work,
        env: { AGENT_DLA_HARVEST_SCRIPT: fake, AGENT_DLA_HARVEST_TIMEOUT_MS: '30000' },
      });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      assert.equal(ev.filter((e) => e.event === 'proxies-refresh').length, 0);
      assert.ok(!fs.readFileSync(path.join(work, 'proxies.txt'), 'utf8').includes('must not appear'));
      assert.equal(H.sha256(path.join(work, 'out.bin')), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('failed harvest still completes direct', { timeout: 120000 }, async () => {
    const work = H.workdir('proxy-refresh-fail');
    const { src, srv } = await setupFile(work);
    try {
      fs.writeFileSync(path.join(work, 'proxies.txt'), 'http://127.0.0.1:1\n');
      const failer = path.join(work, 'fail-harvest.js');
      fs.writeFileSync(failer, 'process.exit(1);\n');
      const r = await H.runAccel([srv.url('/f.bin'), '-o', path.join(work, 'out.bin'), '-n', '2', '--json'], {
        cwd: work,
        env: { AGENT_DLA_HARVEST_SCRIPT: failer, AGENT_DLA_HARVEST_TIMEOUT_MS: '30000' },
      });
      assert.equal(r.code, 0);
      const ev = H.events(r.stdout);
      const dones = ev.filter((e) => e.event === 'proxies-refresh' && e.phase === 'done');
      assert.equal(dones.length, 1);
      assert.equal(dones[0].ok, false);
      assert.equal(H.sha256(path.join(work, 'out.bin')), src.hash);
    } finally {
      await srv.close();
    }
  });

  it('explicit missing proxy file still exits 1', { timeout: 60000 }, async () => {
    const work = H.workdir('proxy-refresh-missing');
    const r = await H.runAccel(['http://127.0.0.1:9/nope', '-p', 'nope.txt', '-o', path.join(work, 'out.bin')], { cwd: work });
    assert.equal(r.code, 1);
    assert.ok(/Proxy file not found/.test(r.stderr));
  });
});
