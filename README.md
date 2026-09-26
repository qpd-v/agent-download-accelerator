# Agent Download Accelerator (`agent-dla`)

Node.js CLI that downloads one file over many parallel connections. Splits the
file into byte-range chunks, downloads them concurrently (optionally spread
across mirrors and proxies) straight into place, then verifies. Failed chunks
requeue with backoff; a manifest + partial file persist progress so rerunning
resumes with byte-level granularity — even mid-chunk bytes survive kills. Pure
JavaScript, no native dependencies. Requires Node >= 22.

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
| `-n, --connections <n>` | parallel connections, 1-128 (default 8; 16-32 for throttled hosts; at most 32 transfer concurrently) |
| `-p, --proxies <file>` | proxy list (default: `./proxies.txt` if present; bare `ip:port` lines accepted) |
| `--mirror <url>` | identical file on another host (repeatable; bad mirrors are evicted per run) |
| `--timeout/--retries/--max-retries` | per-request ms / attempts per round / requeue rounds per chunk (default 100, max 1000; 0 = single attempt) |
| `--deadline <ms>` | abort the whole download after this long (0 = none) |
| `--header "Name: value"` | extra request header, e.g. bearer tokens (repeatable; only sent to the original URL's origin — never to redirect targets, mirrors, or bench checks; never override Range) |
| `--sha256/--expect-size/--max-size/--expect-type` | integrity and safety guards (bad output is deleted) |
| `--allow-html` | save text/html responses instead of refusing |
| `--overwrite` | allow overwriting an existing file that has a server-chosen name (explicit `-o` always allows) |
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

- Every chunk response must be 206 with a matching Content-Range and exact
  byte count; the final size is always checked. A wrong file with exit 0 is
  treated as the worst possible outcome.
- Path-scoped errors: a failure from one proxy or mirror evicts that path;
  only the direct primary can fail the file. Expired signed links (401/403/410
  from a redirect) trigger a re-probe of the original URL. `If-Range`
  validators (strong ETags, primary only) guard against the file changing
  mid-download; stale ranges fall back to single-stream.
- Redirects are capped at 10 hops, non-HTTP targets and https-to-http
  downgrades refused. `--header` values only go to the original URL's origin.
- Server-chosen filenames are sanitized (no traversal, no dotfiles, no
  tool-file collisions) and never overwrite an existing file unless `-o` or
  `--overwrite` is given (`--overwrite` truncates; resume needs a sidecar or
  manifest proving this tool made the partial). Batch collisions get unique
  `(1)` suffixed names.
- A finished download writes a receipt; reruns trust size+receipt (or
  `--sha256`), never size alone. Resume identity ignores URL query strings
  so refreshed presigned URLs resume the same file.
- Each mirror must byte-match a 1KB sample of the primary before serving
  chunks; mismatches are evicted (warns without `--sha256`).
- `--list` lines must be valid http(s) URLs or they are skipped without retries.
- Probing has its own small budget; DNS and local filesystem errors fail fast.
  `--deadline` cancels in-flight requests, it doesn't just stop new attempts.
- `harvestScript`/`insecure`/`mirrors`/`proxies` are only honored from an
  explicit `--config` — a config file sitting in the working directory cannot
  run code, disable TLS, or route traffic.

## Config file (`agent-dla.json`)

Defaults for connections, proxies, mirrors, outputDir, timeout, retries,
maxRetries, deadline, header, harvestTimeout, harvestScript, json, insecure,
redact, overwrite, allowHtml, autoRefresh. CLI flags override it. Note:
`harvestScript`, `insecure`, `mirrors`, and `proxies` in an auto-loaded
`./agent-dla.json` are ignored with a warning — pass `--config` to allow them.

## Tests

```
npm test
```
