# prototype-polluter

Take a list of URLs and check each for **client-side prototype pollution** by appending `__proto__[testparam]=testval` and verifying that the rendered page exposes `window.testparam === 'testval'`.

Built on top of [detectify/page-fetch](https://github.com/detectify/page-fetch) for headless rendering.

## Install

Requires Go 1.17+.

```bash
go install github.com/PiyushThePal/prototype-polluter@latest
```

`page-fetch` is auto-installed on first run if not already on `PATH`. Make sure `$GOPATH/bin` (or `$HOME/go/bin`) is in your `PATH`.

## Usage

```bash
prototype-polluter -h
```

Pipe URLs in via stdin:

```bash
cat domains-list.txt | prototype-polluter
```

Verbose mode also shows non-vulnerable results:

```bash
cat domains-list.txt | prototype-polluter -v
```

Combine with `waybackurls` for live recon:

```bash
waybackurls example.com | prototype-polluter -v
```

## How it works

For each URL on stdin:
1. Append `?__proto__[testparam]=testval` (or `&...` if a query string already exists).
2. Render the URL with `page-fetch` and evaluate `window.testparam == 'testval' ? 'Vulnerable' : 'Not Vulnerable'`.
3. Print `Vulnerable --> <url>` for hits.

False positives are possible — manually verify before reporting.

## Authorization

For authorized security testing only — bug bounty programs in scope, your own assets, or explicit pentest engagements. Spraying prototype-pollution probes at targets you don't have permission to test is not OK.

## License

MIT
