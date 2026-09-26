// Harvest no-signup free HTTP proxies, live-test each, write winners to proxies.txt
// Usage: node get-proxies.js [outFile]  (default: ./proxies.txt next to this script)
const fs = require('fs');
const http = require('http');
const path = require('path');
const { HttpProxyAgent } = require('http-proxy-agent');

const DIR = __dirname;
const OUT_FILE = process.argv[2] || path.join(DIR, 'proxies.txt');
if (require.main === module && (process.argv[2] === '--help' || process.argv[2] === '-h')) {
  console.log('Usage: node get-proxies.js [outFile]  (default: ./proxies.txt next to this script)');
  process.exit(0);
}
const SOURCES = [
  'https://raw.githubusercontent.com/proxmint/free-proxy-list/main/http.txt',
  'https://raw.githubusercontent.com/ProxyScrape/free-proxy-list/main/proxies/http.txt',
  'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
  'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
  'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
];
const MAX_CANDIDATES = 300;
const CONC = 30;
const TIMEOUT = 8000;

function fetchText(url) {
  return new Promise((resolve) => {
    const lib = url.startsWith('https') ? require('https') : http;
    const req = lib.get(url, { timeout: TIMEOUT, headers: { 'User-Agent': 'agent-dla-harvest/1.0' } }, (res) => {
      if (res.statusCode !== 200) { res.resume(); resolve(''); return; }
      let d = '';
      res.on('data', (c) => { d += c; if (d.length > 2e6) { req.destroy(); resolve(d); } });
      res.on('end', () => resolve(d));
      res.on('error', () => resolve(d));
    });
    req.on('timeout', () => { req.destroy(); resolve(''); });
    req.on('error', () => resolve(''));
  });
}

function via(proxy, target, headers) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const req = http.request(target, {
      method: 'GET',
      headers,
      agent: new HttpProxyAgent(`http://${proxy}`),
      timeout: TIMEOUT,
    }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, ms: Date.now() - t0 }));
      res.on('error', () => resolve(null));
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
    req.end();
  });
}

async function main() {
  const seen = new Set();
  // raw lists
  for (const src of SOURCES) {
    const txt = await fetchText(src);
    const n0 = seen.size;
    txt.split(/\r?\n/).forEach((l) => {
      const m = /(?:https?:\/\/)?(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})/.exec(l.trim());
      if (m && !l.includes('@')) seen.add(`${m[1]}:${m[2]}`);
    });
    console.log(`${src.split('/').slice(-2).join('/')} -> ${seen.size - n0} new (${seen.size} total)`);
    if (seen.size >= MAX_CANDIDATES) break;
  }
  // geonode JSON API (no key)
  try {
    const g = await fetchText('https://proxylist.geonode.com/api/proxy-list?limit=100&page=1&sort_by=lastChecked&sort_type=desc');
    const j = JSON.parse(g);
    let n = 0;
    for (const p of j.data || []) {
      if ((p.protocols || []).some((x) => /https?/.test(x))) { if (!seen.has(`${p.ip}:${p.port}`)) { seen.add(`${p.ip}:${p.port}`); n++; } }
    }
    console.log(`geonode -> ${n} new (${seen.size} total)`);
  } catch { console.log('geonode -> failed'); }

  const cands = [...seen].slice(0, MAX_CANDIDATES);
  console.log(`Testing ${cands.length} candidates...`);
  const winners = [];
  const queue = [...cands];
  let tested = 0;
  await Promise.all(Array.from({ length: CONC }, async () => {
    while (queue.length) {
      const px = queue.shift();
      const basic = await via(px, 'http://httpbin.org/ip', {});
      tested++;
      if (tested % 50 === 0) process.stdout.write(`\r${tested}/${cands.length} tested, ${winners.length} working  `);
      if (basic && basic.status === 200) {
        const rg = await via(px, 'http://httpbin.org/range/4096', { Range: 'bytes=0-99' });
        if (rg && (rg.status === 206 || rg.status === 200)) winners.push({ px, ms: basic.ms });
      }
    }
  }));
  console.log(`\n${winners.length} working of ${cands.length}`);
  winners.sort((a, b) => a.ms - b.ms);
  const out = winners.map((w) => `http://${w.px}`).join('\n') + '\n';
  fs.writeFileSync(OUT_FILE, out);
  winners.slice(0, 20).forEach((w) => console.log(`${w.px} ${w.ms}ms`));
}
if (require.main === module) main().catch((e) => { console.error(e.message); process.exit(1); });
module.exports = { main };
