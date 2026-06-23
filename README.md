# DeploySentry

DeploySentry is a defensive web surface and deployment exposure monitor for authorized security testing. It enumerates subdomains, resolves DNS records, probes HTTP/HTTPS services, checks for exposed deployment files, and generates safe reports without dumping secrets or exploiting vulnerabilities.

> DeploySentry is intended for authorized defensive scanning only. Only scan domains you own or have permission to test.

![Alt text](/screenshot.png?raw=true "TUI")

## Features

- Textual terminal UI
- Direct CLI scan mode
- Certificate Transparency subdomain lookup through crt.sh
- Common subdomain fallback wordlist
- A, AAAA, and CNAME resolution
- HTTP/HTTPS probing with title, headers, redirects, and technology hints
- Safe checks for `.env`, `.git`, lockfiles, source maps, debug pages, logs, backups, and SQL dumps
- Soft-404 / wildcard response handling
- JSON, HTML, and Markdown reports
- Optional proxy routing support
- Optional Tor routing support
- API-key gated Pro Verification Mode scaffold

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# for socks4/socks5 proxy or Tor support
pip install -e '.[socks]'
```

## Usage

Interactive TUI:

```bash
deploysentry
```

Direct scan mode:

```bash
deploysentry scan example.com
deploysentry scan example.com --report html
deploysentry scan example.com --report json
deploysentry scan example.com --report markdown
deploysentry scan example.com --concurrency 30
deploysentry scan example.com --timeout 10
deploysentry scan example.com --output ./reports
```

Network routing examples:

```bash
deploysentry scan example.com --proxies proxies.txt --proxy-mode rotate
deploysentry scan example.com --proxies proxies.txt --proxy-mode sticky
deploysentry scan example.com --tor
deploysentry scan example.com --tor --tor-proxy socks5://127.0.0.1:9050
deploysentry scan example.com --pro
DEPLOYSENTRY_API_KEY=your-key deploysentry scan example.com --pro
```

Tor and custom proxies are mutually exclusive in this MVP.

## Proxy file format

Default filename: `proxies.txt`

```text
http://username:password@hostname:port
https://hostname:port
socks4://hostname:port
socks5://username:password@hostname:port
```

Blank lines and comments starting with `#` are ignored. Credentials are redacted in logs and reports.

## Reports

Reports are saved under:

```text
deploysentry-reports/<domain>/<timestamp>/
```

Each scan can produce:

- `report.json`
- `report.html`
- `report.md`

Reports include scan metadata, assets, live services, findings by severity, recommendations, and network verification metadata. Reports never include secret values, API keys, proxy credentials, or sensitive response bodies.

## Screenshots

Screenshots placeholder:

```text
┌ DEPLOYSENTRY // Deployment Exposure Monitor ───────────────┐
│ Target: example.com                    [ Start Scan ]     │
├ Assets / Subdomains ──────────┬ Findings ────────────────┤
│ app.example.com               │ CRITICAL /.env            │
└ Live Log ─────────────────────────────────────────────────┘
```

## Safety and legal note

Use DeploySentry only on domains that you own or are explicitly authorized to test. DeploySentry does not exploit vulnerabilities, clone repositories, brute force credentials, bypass authentication, or dump secrets. It only checks for known safe paths and stores redacted evidence.

## Roadmap

- Persistent SQLite storage
- Plugin system for custom detectors
- Better technology fingerprinting
- Distributed Pro Verification API implementation
- Richer route-difference comparison
- Screenshot capture for authenticated internal testing
- CI and packaged releases

## TUI keyboard shortcuts

The interactive TUI uses input-safe shortcuts so the domain field remains editable across Textual versions and terminals:

- `Enter` while focused in the domain field: start scan
- `Ctrl+S`: start scan
- `Ctrl+X`: stop scan
- `Ctrl+L`: clear log
- `Ctrl+R`: generate report
- `Ctrl+Q`: quit
- `Ctrl+Y`: configure/enable proxies
- `Ctrl+T`: test/enable Tor
- `Ctrl+P`: verify/enable Pro Verification

If the cursor is not already in the Target field when the app opens, press `Tab` until it is focused.

### TUI network toggles

The interactive TUI includes network mode buttons in the top panel:

- `Enable Proxies` / `Disable Proxies`, shortcut `Ctrl+Y`
- `Enable Tor` / `Disable Tor`, shortcut `Ctrl+T`
- `Enable Pro` / `Disable Pro`, shortcut `Ctrl+P`

Tor mode uses `socks5://127.0.0.1:9050` and requires Tor to already be running locally. Pro Verification Mode requires `DEPLOYSENTRY_API_KEY` to be set in the environment when launching the TUI.

Resolved subdomains now update the Assets table with A, AAAA, and CNAME records as DNS results arrive. Discovered assets, DNS resolutions, and live services also appear as INFO rows in the Findings table so the right-hand panel is useful even before high-severity exposure findings are discovered.

## Shodan Passive Enrichment

DeploySentry passively checks Shodan host pages for every discovered A record, using the current network route when Tor or proxies are enabled. This reads `https://www.shodan.io/host/<ip>` and parses general host information, banners, and ports already indexed by Shodan. It is not active port verification and does not connect to target ports.