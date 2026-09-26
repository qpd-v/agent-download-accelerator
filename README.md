# Agent Download Accelerator (`agent-dla`)

Node.js CLI that downloads one file over many parallel connections. Splits the
file into byte-range chunks, downloads them concurrently (optionally spread
across mirrors and proxies), then merges. Failed chunks requeue with backoff;
completed parts persist so rerunning resumes. Pure JavaScript, no native
dependencies. Requires Node >= 18.

## Install

```
npm install -g agent-download-accelerator
```

Or from source:

```
npm install --no-audit --no-fund
npm link
```

## Usage

```
agent-dla "<url>" [-o <file>] [-n <connections>] [-p <proxies>] [--mirror <url>]...
```

Always quote URLs in PowerShell (bare `&` breaks parsing).

| Option | Meaning |
|---|---|
| `-o, --output <file>` | output file path |
| `--dir <folder>` | download into this folder (created if needed) |
| `--list <file>` | batch mode: one URL per line (`#` comments) |
| `--config <file>` | config file (default: `./agent-dla.json` if present) |
| `-n, --connections <n>` | parallel connections, 1-128 (default 8; 16-32 for throttled hosts) |
| `-p, --proxies <file>` | proxy list (default: `./proxies.txt` if present) |
| `--mirror <url>` | identical file on another host (repeatable; chunks round-robin) |
| `--timeout/--retries/--max-retries` | per-request ms / attempts per round / requeue rounds per chunk (default 100, max 1000) |
| `--sha256/--expect-size/--max-size/--expect-type` | integrity and safety guards (bad output is deleted) |
| `-k, --insecure` | allow self-signed certs (target connections only) |
| `--no-auto-refresh` | never auto-refresh the proxy list |
| `--redact` | redact URL queries/credentials in human logs too |
| `--json` | newline-delimited JSON events on stdout (human logs go to stderr) |

Exit codes: 0 complete, 1 download failed, 2 usage/config error.

## Proxies

One `http://[user:pass@]host:port` or `socks5://...` per line, `#` comments.
Lists are capped at 2048 entries; benchmarking runs at most 32 concurrent probes.
Slow/dead proxies are dropped and chunks fall back to direct.

Proxy self-heal: when a proxy file is in use but empty or nothing in it survives
the startup benchmark, the list is auto-refreshed once via `get-proxies.js`
(the old file is backed up to `.bak`) and re-checked. No proxy file means
direct, no harvest. Opt out with `--no-auto-refresh`. Manual refresh:
`node get-proxies.js [outFile]`. Free public proxies are flaky and usually
slower than direct; they are for IP rotation, not speed.

Credentials in proxy URLs are never printed or emitted (shown as
`scheme://host:port`). URLs in JSON events always omit credentials, query
strings, and fragments; `--redact` extends that to human logs.

## Safety

- Redirects are capped at 10 hops, non-HTTP targets refused, https-to-http
  downgrades refused.
- Server filenames that collide with tool files (`proxies.txt`,
  `agent-dla.json`, ...) are refused unless `-o` is given.
- `--list` lines must be valid http(s) URLs or they are skipped without retries.

## Config file (`agent-dla.json`)

Defaults for connections, proxies, mirrors, outputDir, timeout, retries,
maxRetries, harvestTimeout, harvestScript, json, insecure, redact,
autoRefresh. CLI flags override it.

## Tests

```
npm test
```
