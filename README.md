# APISN1P3R

API recon and security testing helper for bug bounty workflows.

```
 █████  ██████  ██ ███████ ███    ██  ██ ██████  ██████  ██████
██   ██ ██   ██ ██ ██      ████   ██ ███ ██   ██      ██ ██   ██
███████ ██████  ██ ███████ ██ ██  ██  ██ ██████   █████  ██████
██   ██ ██      ██      ██ ██  ██ ██  ██ ██           ██ ██   ██
██   ██ ██      ██ ███████ ██   ████  ██ ██      ██████  ██   ██
```

**Author:** c0d3Ninja

---

## Features

- Path discovery and endpoint probing
- CORS testing
- HTTP method testing (`GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD/TRACE`)
- Security header audit (missing/weak/leaky headers)
- Auth bypass probes (header tricks, path tricks, method tricks)
- JWT deep testing with stricter false-positive filtering
- GraphQL endpoint + introspection checks
- **Swagger/OpenAPI** spec discovery & endpoint extraction
- **OAuth2/OIDC** discovery endpoint detection
- **SOAP/WSDL** discovery & operation extraction
- **WebSocket** endpoint detection
- **JSON-RPC / XML-RPC** endpoint discovery
- **AsyncAPI** (event-driven) spec discovery
- WAF/firewall fingerprinting
- Technology stack fingerprinting
- TLS/certificate inspection
- Rate-limit checks
- JSON report export

---

## Requirements

- Python 3.8+
- `requests`
- `urllib3`
- `PyYAML` (optional, for YAML Swagger/AsyncAPI specs)

Install:

```bash
pip install requests urllib3
pip install pyyaml  # optional, for YAML spec parsing
```

---

## Usage

```bash
python3 apisn1p3r.py -u https://api.target.com
```

Output mode:

- Default: findings-only (quiet)
- `-v, --verbose`: full scan logs, module banners, and detailed output

### Input Options

- `-u, --url` single target
- `-f, --file` file with targets (one per line)
- `--stdin` read targets from stdin

Examples:

```bash
python3 apisn1p3r.py -u https://api.target.com
python3 apisn1p3r.py -f targets.txt -m paths,cors
cat urls.txt | python3 apisn1p3r.py --stdin -m waf,tech
```

---

## Modules

Use `-m` with comma-separated values:

- `paths` - directory/path discovery
- `cors` - CORS misconfiguration checks
- `methods` - HTTP method behavior
- `headers` - security header audit
- `auth` - auth bypass probes
- `jwt` - JWT exploit checks (alg confusion, claim manipulation, IDOR-style response diffing)
- `graphql` - GraphQL detection + introspection
- `swagger` - Swagger/OpenAPI spec discovery & endpoint extraction
- `oauth2` - OAuth2/OIDC discovery (`.well-known/openid-configuration`, etc.)
- `soap` - SOAP/WSDL discovery & operation extraction
- `websocket` - WebSocket endpoint detection
- `jsonrpc` - JSON-RPC / XML-RPC endpoint discovery
- `asyncapi` - AsyncAPI (event-driven) spec discovery
- `waf` - WAF/firewall detection
- `tech` - technology fingerprinting
- `tls` - TLS/cert analysis
- `ratelimit` - burst/rate-limit checks
- `all` - run everything (default)

Examples:

```bash
python3 apisn1p3r.py -u https://api.target.com -m jwt
python3 apisn1p3r.py -u https://api.target.com -m headers,auth,graphql
python3 apisn1p3r.py -u https://api.target.com -m swagger,oauth2,soap
python3 apisn1p3r.py -u https://api.target.com -m waf,tech,tls
```

---

## Useful Flags

- `-w, --wordlist` custom path wordlist
- `--timeout` request timeout (default: `10`)
- `--rate-count` number of rapid requests for rate-limit test (default: `20`)
- `--processes` concurrent worker threads for `paths` and GraphQL endpoint discovery (default: `1`)
- `--graphql-probe-timeout` fast probe timeout for GraphQL path discovery (default: `4`)
- `--graphql-max-endpoints` max GraphQL endpoints to introspect per target (default: `1`)
- `--user-agent` custom user-agent string
- `-o, --output` save JSON output
- `-v, --verbose` verbose output

Example:

```bash
python3 apisn1p3r.py -u https://api.target.com --timeout 20 --processes 8 -o results.json
python3 apisn1p3r.py -f targets.txt -m graphql --processes 8 --graphql-probe-timeout 3 --graphql-max-endpoints 1
```

---

## JWT Module Notes

The JWT module is tuned to reduce false positives:

- It first checks auth state with:
  - no auth header
  - invalid token
  - forged `alg:none` token
- It only reports findings when there is a real auth-state delta on protected endpoints.
- Public `200 OK` endpoints are not treated as confirmed JWT bypasses.

This makes results safer to use in bug bounty reports.

---

## Output

When `-o` is used, the JSON report includes:

- `paths`
- `waf`
- `technologies`
- `security_headers`
- `auth_bypass`
- `jwt_exploit`
- `graphql`
- `swagger` (specs, endpoints)
- `oauth2` (discovery endpoints, issuer, token URL)
- `soap` (WSDL endpoints, operations)
- `websocket` (detected endpoints)
- `jsonrpc` (JSON-RPC/XML-RPC endpoints)
- `asyncapi` (event-driven API specs)

---

## Legal

Use only on assets you are explicitly authorized to test (bug bounty scope, written permission, or owned systems).
