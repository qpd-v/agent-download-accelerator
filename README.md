# Agent Download Accelerator (`agent-dla`)

Node.js CLI that downloads one file over many parallel connections. Splits the
file into byte-range chunks, downloads them concurrently (optionally spread
across mirrors and proxies) straight into place, then verifies. Failed chunks
requeue with backoff; a manifest + partial file persist progress so rerunning
resumes with byte-level granularity — even mid-chunk bytes survive kills. Pure
JavaScript, no native dependencies. Requires Node >= 22.

## Install

```
npm install -g agent-dla
```

One-off, without installing: `npx agent-dla <url>`.

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
  from a redirect) trigger a re-probe of the original URL; a revoked link
  (definitive origin 4xx on re-probe, twice in a row) aborts fast while a
  one-off 403 gets a second chance, a 403/429 with Retry-After waits once,
  and transient outages requeue. This applies to chunked and single-stream
  (`-n 1`, no-Range servers) downloads alike. A fresh link is used right
  away (no backoff), and there is no limit on refreshes that keep delivering
  bytes, so long downloads over short-lived links finish; 5 refreshes in a
  row that deliver nothing abort.
  `If-Range` validators (strong ETags, primary only; single-stream resume too)
  guard against the file changing mid-download; stale ranges fall back to
  single-stream, repeated validator flapping falls back as well — resumed
  bytes are never mixed across versions.
- Redirects are capped at 10 hops, non-HTTP targets and https-to-http
  downgrades refused. `--header` values only go to the original URL's origin,
  and are withheld from plain-http proxy requests (as are URL-embedded
  credentials `http://user:pw@host`, with a warning) — a proxy would see them
  in the clear.
- Server-chosen filenames are sanitized (no traversal, no dotfiles, no
  tool-file collisions) and never overwrite an existing file unless `-o` or
  `--overwrite` is given (`--overwrite` truncates; resume needs a sidecar or
  manifest proving this tool made the partial). Batch collisions get unique
  `(1)` suffixed names.
- A finished download writes a receipt to a hidden per-directory store
  (`.agent-dla/receipts/<name>.json`, one file per output, atomic writes);
  reruns trust size+receipt (or `--sha256`), never size alone. Parallel runs
  into one directory are safe; a corrupt receipt affects only its own file.
  Two runs into the *same* output are refused: the second exits 1 while
  `<out>.partial.lock` (holding the owner's pid) exists. A lock left by a
  killed run is taken over automatically; if a reused pid keeps a stale lock
  alive, the error names the file to delete.
  Resume identity keeps the URL query string, except signature/expiry
  parameters (`X-Amz-*`, `X-Goog-*`, `Signature`, `Expires`, `Key-Pair-Id`,
  `Policy`, `sig`, `se`, `sp`, `sv`, `st`, `sr`) which are dropped (`token` is kept: it often selects the file) —
  so `?id=1` vs `?id=2` never share a manifest (even with identical ETags),
  while a refreshed presigned URL resumes the same file with or without an
  ETag.
  A republished file (validator change) restarts clean instead of mixing versions.
  State files (`<out>.manifest.json`, receipts, `<out>.single.json`) hold a SHA-256 of the
  identity key and a redacted URL: no userinfo, signed-link parameters or tokens.
  Identity does not include credentials: if the same URL serves different
  content per account (userinfo, `--header "Authorization: ..."`, cookies),
  use a distinct `-o` name per account so receipts and partials are not shared.
  Server-chosen names ending in `.partial`, `.manifest.json`, `.single.json`,
  `.receipt.json` or `.partial.lock` are refused (use `-o`).
  If the server sends neither ETag nor Last-Modified, a same-size republish
  during a resume cannot be detected; the tool warns once when resuming in
  that case. Pass `--sha256` to verify the result.
- Each mirror must byte-match first- and last-1KB samples of the primary
  before serving chunks; mismatches are evicted (warns without `--sha256`).
- `--list` lines must be valid http(s) URLs or they are skipped without retries.
- Probing has its own small budget; DNS and local filesystem errors fail fast.
  `--deadline` cancels in-flight requests and bounds waits (Retry-After,
  backoff, harvest) — it doesn't just stop new attempts.
- `harvestScript`/`insecure`/`mirrors`/`proxies`/`headers`/`outputDir` are only
  honored from an explicit `--config` — a config file sitting in the working
  directory cannot run code, disable TLS, route traffic, add credentials, or
  redirect output.

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
