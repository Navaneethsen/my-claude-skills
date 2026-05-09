#!/usr/bin/env python3
"""
URL Triage — passive, zero-infection OSINT triage for suspicious URLs.

Usage:
    python3 triage.py <URL> [--report-dir DIR] [--vt-key KEY] [--otx-key KEY]
                      [--urlhaus-key KEY] [--threatfox-key KEY] [--emailrep-key KEY]
                      [--pulsedive-key KEY] [--whoisxml-key KEY]

Never executes JavaScript. Never submits to public scanners (search-only).
Queries: urlscan.io, crt.sh, Google DoH, Cloudflare DoH, RDAP, VirusTotal,
AlienVault OTX, Shodan InternetDB, PhishStats, URLhaus (abuse.ch), ThreatFox (abuse.ch),
HackerTarget Reverse IP, OpenPhish, EmailRep.io, Pulsedive, WhoisXML Reverse WHOIS.
Produces report.md + raw/*.json.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

UA_DESKTOP = "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"
UA_MOBILE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
UA_CURL = "curl/8.4.0"
TIMEOUT = 20

ABUSED_TLDS = {"top", "shop", "icu", "xyz", "cfd", "zip", "mov", "click", "sbs",
               "cc", "buzz", "rest", "bond", "autos", "cyou", "quest", "monster"}
BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "office365", "o365", "outlook",
    "chase", "wellsfargo", "bankofamerica", "hsbc", "barclays", "revolut",
    "coinbase", "binance", "metamask", "ledger", "trustwallet", "phantom",
    "usps", "ups", "fedex", "dhl", "postnl", "royalmail", "an-post", "correos",
    "digid", "ing", "abn", "rabobank", "bnp", "société générale",
    "netflix", "spotify", "linkedin", "facebook", "instagram", "whatsapp",
    "docusign", "dropbox", "onedrive", "google", "gmail",
]
CRYPTO_PATTERNS = {
    "BTC":  re.compile(r"\b(bc1[0-9a-z]{25,62}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b"),
    "ETH":  re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "TRX":  re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
    "SOL":  re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"),  # noisy, filter by context
}
CONTACT_PATTERNS = {
    "telegram": re.compile(r"(?:t\.me|telegram\.me)/([A-Za-z0-9_]{5,})", re.I),
    "whatsapp": re.compile(r"wa\.me/(\+?\d{7,15})", re.I),
    "email":    re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}"),
    "phone":    re.compile(r"\+\d[\d\s\-().]{7,}\d"),
}
SUSPICIOUS_PORTS = {8080, 8443, 8888, 4444, 1337, 31337, 9999, 7777}

OPENPHISH_CACHE = Path("/tmp/openphish_feed.txt")
OPENPHISH_TTL = 12 * 3600  # 12 hours


def log(msg: str) -> None:
    print(f"[triage] {msg}", file=sys.stderr, flush=True)


# ---------- HTTP helpers ----------

def http_get(url: str, *, headers: dict | None = None, timeout: int = TIMEOUT,
             method: str = "GET") -> tuple[int, dict, bytes]:
    req = urllib.request.Request(url, method=method, headers=headers or {})
    if "User-Agent" not in (headers or {}):
        req.add_header("User-Agent", UA_DESKTOP)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return 0, {"_error": str(e)}, b""


def http_post(url: str, *, data: dict | None = None, form: dict | None = None,
              headers: dict | None = None, timeout: int = TIMEOUT) -> tuple[int, dict, bytes]:
    """POST with JSON body (data=) or form-encoded body (form=)."""
    hdrs = dict(headers or {})
    if "User-Agent" not in hdrs:
        hdrs["User-Agent"] = UA_DESKTOP
    if data is not None:
        body_bytes = json.dumps(data).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif form is not None:
        body_bytes = urllib.parse.urlencode(form).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    else:
        body_bytes = b""
    req = urllib.request.Request(url, data=body_bytes, method="POST", headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        return 0, {"_error": str(e)}, b""


# ---------- URL parsing helpers ----------

def parse_url(url: str) -> dict:
    p = urllib.parse.urlparse(url)
    host = p.hostname or ""
    parts = host.split(".")
    apex = ".".join(parts[-2:]) if len(parts) >= 2 else host
    tld = parts[-1].lower() if parts else ""
    return {
        "url": url,
        "scheme": p.scheme,
        "host": host,
        "apex": apex,
        "tld": tld,
        "path": p.path,
        "path_segments": [s for s in p.path.split("/") if s],
        "query": p.query,
    }


def defang(s: str) -> str:
    return (s.replace("http://", "hxxp://").replace("https://", "hxxps://")
             .replace(".", "[.]"))


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s.lower())
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------- Intel sources ----------

def doh_query(name: str, rtype: str, server: str = "https://dns.google/resolve") -> dict:
    url = f"{server}?name={urllib.parse.quote(name)}&type={rtype}"
    code, _, body = http_get(url, headers={"Accept": "application/dns-json"})
    if code != 200 or not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def dns_bundle(host: str) -> dict:
    out: dict = {}
    for rtype in ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"]:
        g = doh_query(host, rtype)
        answers = [a.get("data") for a in g.get("Answer", []) if isinstance(a, dict)]
        if answers:
            out[rtype] = answers
    return out


def extract_rdap_email(rdap_data: dict) -> str | None:
    """Extract registrant email from RDAP vcardArray. Checks registrant + sub-entities."""
    if not isinstance(rdap_data, dict):
        return None
    for entity in rdap_data.get("entities", []) or []:
        roles = entity.get("roles", []) or []
        is_registrant = "registrant" in roles or "technical" in roles or not roles
        if not is_registrant:
            continue
        vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
        for item in vcard:
            if isinstance(item, list) and len(item) >= 4:
                if isinstance(item[0], str) and item[0].lower() == "email":
                    val = item[3]
                    if isinstance(val, str) and "@" in val:
                        return val
        # Recurse into sub-entities (registrars often nest contact info)
        for sub in entity.get("entities", []) or []:
            sub_vcard = sub.get("vcardArray", [None, []])[1] if sub.get("vcardArray") else []
            for item in sub_vcard:
                if isinstance(item, list) and len(item) >= 4:
                    if isinstance(item[0], str) and item[0].lower() == "email":
                        val = item[3]
                        if isinstance(val, str) and "@" in val:
                            return val
    return None


def rdap(domain: str) -> dict:
    tld = domain.rsplit(".", 1)[-1]
    servers = {
        "top":  "https://rdap.zdns.cn/domain/",
        "shop": "https://rdap.identitydigital.services/rdap/domain/",
        "xyz":  "https://rdap.centralnic.com/xyz/domain/",
        "icu":  "https://rdap.centralnic.com/icu/domain/",
    }
    server = servers.get(tld, "https://rdap-bootstrap.arin.net/bootstrap/domain/")
    url = server + domain
    code, _, body = http_get(url, headers={"Accept": "application/rdap+json"})
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e), "raw": body[:500].decode("utf-8", "replace")}


def crtsh(domain: str) -> list[dict]:
    url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
    code, _, body = http_get(url, timeout=30)
    if code != 200 or not body:
        return []
    try:
        return json.loads(body)
    except Exception:
        return []


def urlscan_search(query: str) -> dict:
    url = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(query)}&size=50"
    code, _, body = http_get(url)
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def urlscan_result(uuid: str) -> dict:
    code, _, body = http_get(f"https://urlscan.io/api/v1/result/{uuid}/")
    if not body:
        return {}
    try:
        return json.loads(body)
    except Exception:
        return {}


def virustotal_domain(domain: str, api_key: str | None) -> dict:
    if not api_key:
        return {"_skipped": "no VT api key (set VT_API_KEY env or --vt-key)"}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    code, _, body = http_get(url, headers={"x-apikey": api_key})
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def otx_general(domain: str, api_key: str | None) -> dict:
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    code, _, body = http_get(url, headers=headers)
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def shodan_internetdb(ip: str) -> dict:
    """Query Shodan InternetDB — no auth required. Returns ports, vulns, tags."""
    if not ip or ":" in ip:
        return {"_skipped": "ipv6 or empty"}
    code, _, body = http_get(f"https://internetdb.shodan.io/{ip}")
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def phishstats(domain: str) -> list[dict]:
    """Query PhishStats for recent phishing records matching domain. Up to 10 results."""
    url = (f"https://api.phishstats.info/api/phishing"
           f"?_where=(url,like,~{urllib.parse.quote(domain)}~)&_sort=-date&_size=10")
    code, _, body = http_get(url)
    if not body:
        return []
    try:
        data = json.loads(body)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def urlhaus(domain: str, api_key: str | None) -> dict:
    """Query abuse.ch URLhaus for malware URLs on this host. Key optional."""
    code, _, body = http_post(
        "https://urlhaus-api.abuse.ch/v1/host/",
        form={"host": domain},
    )
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def threatfox(domain: str, api_key: str | None) -> dict:
    """Query abuse.ch ThreatFox for IOC matches. Key optional."""
    payload: dict = {"query": "search_ioc", "search_term": domain}
    hdrs: dict = {}
    if api_key:
        hdrs["Auth-Key"] = api_key
    code, _, body = http_post(
        "https://threatfox-api.abuse.ch/api/v1/",
        data=payload,
        headers=hdrs,
    )
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def hackertarget_reverse_ip(ip: str) -> list[str]:
    """Reverse IP lookup via HackerTarget — no auth, 50 req/day free tier."""
    if not ip or ":" in ip:
        return []
    code, _, body = http_get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
    if code != 200 or not body:
        return []
    text = body.decode("utf-8", "replace").strip()
    if "error" in text.lower() or "no records" in text.lower() or not text:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


def openphish_check(url: str, domain: str) -> dict:
    """Check OpenPhish feed (cached 12h). No auth required."""
    feed_lines: list[str] = []
    now = time.time()

    if OPENPHISH_CACHE.exists() and (now - OPENPHISH_CACHE.stat().st_mtime) < OPENPHISH_TTL:
        feed_lines = OPENPHISH_CACHE.read_text(errors="replace").splitlines()
    else:
        code, _, body = http_get("https://openphish.com/feed.txt", timeout=30)
        if code == 200 and body:
            content = body.decode("utf-8", "replace")
            try:
                OPENPHISH_CACHE.write_text(content)
            except OSError:
                pass
            feed_lines = content.splitlines()

    url_lower = url.lower()
    domain_lower = domain.lower()
    url_match = any(url_lower in line.lower() for line in feed_lines if line)
    domain_match = any(domain_lower in line.lower() for line in feed_lines if line)
    return {
        "feed_size": len(feed_lines),
        "url_match": url_match,
        "domain_match": domain_match,
        "in_feed": url_match or domain_match,
    }


def emailrep(email: str, api_key: str | None) -> dict:
    """Query EmailRep.io for registrant email reputation."""
    if not email or not api_key:
        return {"_skipped": "no email or no emailrep key (set EMAILREP_API_KEY)"}
    hdrs = {"Key": api_key, "User-Agent": UA_DESKTOP}
    code, _, body = http_get(
        f"https://emailrep.io/{urllib.parse.quote(email)}", headers=hdrs
    )
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def pulsedive(domain: str, api_key: str | None) -> dict:
    """Query Pulsedive for threat intel risk level and factors."""
    if not api_key:
        return {"_skipped": "no Pulsedive key (set PULSEDIVE_API_KEY)"}
    url = (f"https://pulsedive.com/api/info.php"
           f"?indicator={urllib.parse.quote(domain)}&key={urllib.parse.quote(api_key)}")
    code, _, body = http_get(url)
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def whoisxml_reverse_whois(email: str, api_key: str | None) -> dict:
    """Query WhoisXML Reverse WHOIS in preview mode — returns domain count only (free)."""
    if not email or not api_key:
        return {"_skipped": "no email or no whoisxml key (set WHOISXML_API_KEY)"}
    payload = {
        "apiKey": api_key,
        "searchType": "current",
        "mode": "preview",
        "basicSearchTerms": {"include": [email]},
    }
    code, _, body = http_post(
        "https://reverse-whois.whoisxmlapi.com/api/v2",
        data=payload,
    )
    if not body:
        return {"_error": f"http {code}"}
    try:
        return json.loads(body)
    except Exception as e:
        return {"_error": str(e)}


def passive_fetch(url: str) -> dict:
    """Fetch headers and small body with 3 UAs to detect cloaking.
    Never saves body to disk; returns truncated string for content analysis."""
    result: dict = {"probes": []}
    for label, ua in [("desktop", UA_DESKTOP), ("mobile", UA_MOBILE), ("curl", UA_CURL)]:
        code, headers, body = http_get(url, headers={
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        })
        probe = {
            "ua": label,
            "status": code,
            "server": headers.get("Server"),
            "content_type": headers.get("Content-Type"),
            "content_length": len(body),
            "location": headers.get("Location"),
            "cf_ray": headers.get("cf-ray") or headers.get("CF-RAY"),
            "sha256": hashlib.sha256(body).hexdigest() if body else None,
        }
        if body and len(body) < 500_000:
            probe["body_text"] = body.decode("utf-8", "replace")[:80_000]
        result["probes"].append(probe)
    return result


def analyse_body(text: str) -> dict:
    if not text:
        return {}
    text_lc = text.lower()
    brands = sorted({b for b in BRAND_KEYWORDS
                     if re.search(r"\b" + re.escape(b) + r"\b", text_lc)})
    crypto = {}
    for name, pat in CRYPTO_PATTERNS.items():
        matches = pat.findall(text)
        if matches:
            crypto[name] = sorted(set(matches))[:10]
    contacts = {}
    for name, pat in CONTACT_PATTERNS.items():
        matches = pat.findall(text)
        if matches:
            contacts[name] = sorted(set(matches))[:10]
    forms = re.findall(r'<form[^>]*action\s*=\s*["\']([^"\']+)', text, re.I)
    scripts = re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)', text, re.I)
    iframes = re.findall(r'<iframe[^>]+src\s*=\s*["\']([^"\']+)', text, re.I)
    meta_refresh = re.findall(
        r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+content\s*=\s*["\']([^"\']+)',
        text, re.I)
    title = re.search(r"<title[^>]*>([^<]+)</title>", text, re.I)
    lang = re.search(r'<html[^>]+lang\s*=\s*["\']([^"\']+)', text, re.I)
    has_password = bool(re.search(r'<input[^>]+type\s*=\s*["\']password', text, re.I))
    return {
        "title": title.group(1).strip() if title else None,
        "lang": lang.group(1) if lang else None,
        "brands": brands,
        "crypto_addresses": crypto,
        "contacts": contacts,
        "form_actions": sorted(set(forms))[:20],
        "external_scripts": sorted(set(scripts))[:30],
        "iframes": sorted(set(iframes))[:20],
        "meta_refresh": meta_refresh,
        "has_password_input": has_password,
    }


# ---------- Scoring ----------

def score(signals: dict) -> tuple[int, list[str]]:
    s = 0
    fired: list[str] = []

    age = signals.get("domain_age_days")
    if age is not None:
        if age < 7:
            s += 25; fired.append(f"Domain age {age}d (<7 days)")
        elif age < 30:
            s += 15; fired.append(f"Domain age {age}d (<30 days)")

    tld = signals.get("tld")
    if tld in ABUSED_TLDS:
        s += 8; fired.append(f".{tld} TLD (heavily abused for phishing)")

    apex = signals.get("apex", "")
    sld = apex.split(".")[0] if apex else ""
    if sld and entropy(sld) > 3.5 and not any(b in sld for b in BRAND_KEYWORDS):
        s += 7; fired.append(f"Random/high-entropy domain name '{sld}'")

    segs = signals.get("path_segments", [])
    for seg in segs:
        if len(seg) >= 16 and entropy(seg) > 3.5:
            s += 10; fired.append(f"Per-victim token in path: '{seg[:12]}…' (len {len(seg)})")
            break

    probes = signals.get("probes", [])
    statuses = {p["ua"]: p["status"] for p in probes}
    if len(set(statuses.values())) > 1 and 0 not in set(statuses.values()):
        s += 15; fired.append(f"Cloaking — different HTTP status per UA: {statuses}")

    urlscan_verdict = signals.get("urlscan_ml_malicious")
    # Only weight urlscan ML if domain is young (<180d) — old domains have noisy historical scans
    if urlscan_verdict and (age is None or age < 180):
        s += 15; fired.append("urlscan.io ML flagged as malicious")

    vt_hits = signals.get("vt_malicious_engines", 0)
    if vt_hits >= 3:
        s += 15; fired.append(f"VirusTotal: {vt_hits} engines flag as malicious")
    elif vt_hits > 0:
        s += 8; fired.append(f"VirusTotal: {vt_hits} engine flags")

    if signals.get("brand_impersonation"):
        s += 15; fired.append(f"Brand impersonation in content: {signals['brand_impersonation']}")

    if signals.get("cloudflare") and age is not None and age < 30:
        s += 2; fired.append("Cloudflare proxy + young domain (cheap burn infra)")

    if signals.get("letsencrypt") and age is not None and age < 30:
        s += 3; fired.append("Let's Encrypt cert + young domain")

    if signals.get("has_password_input") and age is not None and age < 30:
        s += 15; fired.append("Credential form on <30-day-old domain")

    if signals.get("crypto_addresses"):
        s += 10; fired.append(f"Crypto wallet addresses on page: {list(signals['crypto_addresses'].keys())}")

    if signals.get("otx_pulses", 0) > 0:
        s += 15; fired.append(f"AlienVault OTX: {signals['otx_pulses']} threat pulses")

    # --- New indicators ---
    if signals.get("urlhaus_hit"):
        cnt = signals.get("urlhaus_url_count", "?")
        s += 20; fired.append(f"URLhaus (abuse.ch): {cnt} malware URLs hosted on domain")

    if signals.get("threatfox_hit"):
        malware = signals.get("threatfox_malware", "unknown malware")
        s += 20; fired.append(f"ThreatFox (abuse.ch): IOC match — {malware}")

    ps_score = signals.get("phishstats_score", 0)
    if ps_score > 8:
        s += 15; fired.append(f"PhishStats score {ps_score}/10 (very high risk)")
    elif ps_score >= 5:
        s += 8; fired.append(f"PhishStats score {ps_score}/10 (elevated risk)")

    if signals.get("openphish_hit"):
        s += 20; fired.append("OpenPhish feed: domain/URL actively listed in phishing feed")

    co_count = signals.get("co_hosted_count", 0)
    if co_count >= 10:
        s += 5; fired.append(f"Shared hosting: {co_count} co-hosted domains (cheap burn infra signal)")

    shodan_vulns = signals.get("shodan_vulns", [])
    if shodan_vulns:
        cve_list = ", ".join(shodan_vulns[:3])
        s += 5; fired.append(f"Shodan: known CVEs on hosting IP: {cve_list}")

    shodan_sus_ports = signals.get("shodan_suspicious_ports", [])
    if shodan_sus_ports:
        s += 3; fired.append(f"Shodan: non-standard open ports: {shodan_sus_ports}")

    if signals.get("emailrep_malicious"):
        s += 10; fired.append("EmailRep.io: registrant email has malicious activity history")

    if signals.get("emailrep_credentials_leaked"):
        s += 5; fired.append("EmailRep.io: registrant email credentials previously leaked")

    pd_risk = signals.get("pulsedive_risk", "")
    if pd_risk in ("high", "critical"):
        s += 12; fired.append(f"Pulsedive risk level: {pd_risk}")

    wx_count = signals.get("whoisxml_domain_count", 0)
    if wx_count > 50:
        s += 10; fired.append(f"WhoisXML Reverse WHOIS: registrant owns {wx_count}+ domains (scam farm signal)")

    if signals.get("privacy_shield") and age is not None and age < 30:
        s += 5; fired.append("Privacy-shielded WHOIS on young domain")

    s = min(s, 100)
    return s, fired


def classify(score_v: int, signals: dict) -> str:
    if signals.get("has_password_input"):
        return "Phishing — Credential Harvesting"
    if signals.get("crypto_addresses"):
        return "Scam — Crypto Drainer / Fraud"
    if signals.get("brand_impersonation") in ("usps", "dhl", "ups", "postnl", "royalmail", "fedex"):
        return "Scam — Fake Delivery / Postal"
    if score_v >= 70:
        return "High-confidence Scam / Phishing"
    if score_v >= 40:
        return "Likely Scam — evidence insufficient for high confidence"
    if score_v >= 15:
        return "Suspicious — monitor"
    return "Inconclusive / possibly benign"


def verdict(score_v: int) -> str:
    if score_v >= 70: return "HIGH-CONFIDENCE MALICIOUS"
    if score_v >= 40: return "LIKELY SCAM"
    if score_v >= 15: return "SUSPICIOUS"
    return "INCONCLUSIVE"


# ---------- Report ----------

def render_report(signals: dict, raw_dir: Path) -> str:
    s = signals
    lines: list[str] = []

    lines.append(f"# URL Triage: `{defang(s['apex'])}`")
    lines.append("")
    lines.append(f"**Verdict:** {s['verdict']}    **Confidence:** {s['score']}/100")
    lines.append(f"**Classification:** {s['classification']}")
    lines.append(f"**Date:** {s['date']}")
    lines.append("")

    lines.append("## TL;DR")
    lines.append(s["tldr"])
    lines.append("")

    lines.append("## Quick Facts")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| URL (defanged) | `{defang(s['url'])}` |")
    age = s.get("domain_age_days")
    age_str = (f"{age} days" +
               (f" (registered {s['domain_registered']})" if s.get("domain_registered") else ""))
    lines.append(f"| Domain age | {age_str if age is not None else 'unknown (registry lag)'} |")
    lines.append(f"| Hosting | {s.get('asn', '?')} ({s.get('asn_country', '?')}) |")
    lines.append(f"| Behind Cloudflare? | {'Yes' if s.get('cloudflare') else 'No'} |")
    lines.append(f"| Cloaking detected? | {'Yes' if s.get('cloaking') else 'No'} |")
    if s.get("language"):
        lines.append(f"| Language targeted | {s['language']} |")
    if s.get("brand_impersonation"):
        lines.append(f"| Brand impersonated | {s['brand_impersonation']} |")
    lines.append("")

    lines.append("## Evidence")
    if not s["fired"]:
        lines.append("- No strong malicious indicators fired. URL may be benign or too new for intel coverage.")
    else:
        for ev in s["fired"]:
            icon = "❌" if s["score"] >= 50 else "⚠️"
            lines.append(f"- {icon} {ev}")
    lines.append("")

    # --- Infrastructure Analysis ---
    ips = s.get("ips", [])
    primary_ip = next((ip for ip in ips if "." in ip), None)
    shodan = s.get("shodan_data", {}) or {}
    co_hosted = s.get("co_hosted_domains", []) or []
    co_count = s.get("co_hosted_count", 0)

    lines.append("## Infrastructure Analysis")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| IP | {primary_ip or 'unknown'} |")
    lines.append(f"| ASN | {s.get('asn', '?')} |")
    lines.append(f"| Country | {s.get('asn_country', '?')} |")
    ports = shodan.get("ports", []) or []
    lines.append(f"| Open ports | {', '.join(str(p) for p in ports) if ports else 'unknown'} |")
    vulns = shodan.get("vulns", []) or []
    lines.append(f"| Known CVEs | {', '.join(str(v) for v in vulns[:5]) if vulns else 'none detected'} |")
    sample = co_hosted[:5]
    co_str = (f"{co_count} domains" +
              (f" (e.g. {', '.join(sample)})" if sample else ""))
    lines.append(f"| Co-hosted domains | {co_str if co_count else 'unknown'} |")
    hosting_type = "CDN" if s.get("cloudflare") else ("Shared" if co_count > 5 else "Dedicated / Unknown")
    lines.append(f"| Hosting type | {hosting_type} |")
    lines.append("")

    # --- Registrant Intelligence ---
    reg_email = s.get("registrant_email")
    erep = s.get("emailrep_data") or {}
    erep_details = erep.get("details", {}) if isinstance(erep, dict) else {}
    privacy = s.get("privacy_shield")

    lines.append("## Registrant Intelligence")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| Registrar | {s.get('registrar', 'unknown')} |")
    lines.append(f"| Privacy shield | {'Yes (' + str(privacy) + ')' if privacy else 'No'} |")
    lines.append(f"| Registrant email | {reg_email or 'hidden / not available'} |")
    if isinstance(erep, dict) and "_skipped" not in erep and "_error" not in erep:
        lines.append(f"| Email reputation | {erep.get('reputation', 'unknown')} |")
        profiles = erep_details.get("profiles", []) or []
        lines.append(f"| Social profiles | {', '.join(profiles[:5]) if profiles else 'none'} |")
        lines.append(f"| Breach exposure | {'Yes' if erep_details.get('credentials_leaked') else 'No'} |")
    wx_count = s.get("whoisxml_domain_count", 0)
    lines.append(f"| Domains by same registrant | {wx_count if wx_count else 'unknown'} |")
    lines.append("")

    # --- Threat Intelligence Cross-Reference ---
    lines.append("## Threat Intelligence Cross-Reference")
    lines.append("| Source | Result |")
    lines.append("|---|---|")
    us_label = "malicious" if s.get("urlscan_ml_malicious") else "no malicious verdict"
    lines.append(f"| urlscan.io | {us_label} |")
    vt_hits = s.get("vt_malicious_engines", 0)
    vt_total = s.get("vt_total_engines", 0)
    if s.get("_has_vt"):
        lines.append(f"| VirusTotal | {vt_hits}/{vt_total} engines |")
    else:
        lines.append("| VirusTotal | no key provided |")
    lines.append(f"| AlienVault OTX | {s.get('otx_pulses', 0)} pulses |")
    ps_score = s.get("phishstats_score", 0)
    ps_count = s.get("phishstats_count", 0)
    ps_label = f"Score {ps_score}/10 ({ps_count} records)" if ps_count else "no records"
    lines.append(f"| PhishStats | {ps_label} |")
    uh_count = s.get("urlhaus_url_count", 0)
    lines.append(f"| URLhaus | {str(uh_count) + ' malware URLs' if uh_count else 'clean'} |")
    tf_hit = s.get("threatfox_hit")
    tf_label = f"IOC match: {s.get('threatfox_malware', 'malware')}" if tf_hit else "no match"
    lines.append(f"| ThreatFox | {tf_label} |")
    lines.append(f"| OpenPhish | {'In feed ✓' if s.get('openphish_hit') else 'not in feed'} |")
    pd_risk = s.get("pulsedive_risk", "")
    pd_label = f"Risk: {pd_risk}" if pd_risk else ("no key provided" if not s.get("_has_pulsedive") else "unknown")
    lines.append(f"| Pulsedive | {pd_label} |")
    lines.append("")

    # --- IOCs ---
    lines.append("## IOCs (defanged)")
    lines.append(f"- **Domain:** `{defang(s['apex'])}`")
    if ips:
        lines.append("- **IPs:** " + ", ".join(f"`{ip.replace('.', '[.]')}`" for ip in ips))
    if s.get("cert_sha256"):
        lines.append(f"- **Cert SHA256:** `{s['cert_sha256']}`")
    if s.get("page_sha256"):
        lines.append(f"- **Page SHA256:** `{s['page_sha256']}`")
    lines.append("")

    if s["score"] >= 15:
        lines.append("## What to do now")
        lines.append("1. **Do not click. Do not enter data. Do not forward.**")
        lines.append("2. Report:")
        if s.get("cloudflare"):
            lines.append("   - Cloudflare abuse: https://abuse.cloudflare.com/")
        lines.append("   - Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/")
        lines.append("   - PhishTank: https://phishtank.org/add_web_phish.php")
        lines.append(f"   - Registry abuse: `abuse@nic.{s['tld']}`")
        lines.append("3. If URL arrived via SMS → forward to **7726** (spam).")
        lines.append("4. If data or money already given → rotate creds, notify bank, freeze card.")
        lines.append("")
        lines.append("## Block list (copy-paste)")
        lines.append("```")
        lines.append(s["apex"])
        for ip in ips:
            lines.append(ip)
        lines.append("```")
        lines.append("")

    sources = ["urlscan.io", "crt.sh", "Google DoH", "Cloudflare DoH", "RDAP",
               "Shodan InternetDB", "PhishStats", "URLhaus", "ThreatFox",
               "HackerTarget Reverse IP", "OpenPhish"]
    if s.get("_has_vt"):
        sources.append("VirusTotal")
    if s.get("_has_otx"):
        sources.append("AlienVault OTX")
    if s.get("_has_pulsedive"):
        sources.append("Pulsedive")
    if s.get("_has_emailrep"):
        sources.append("EmailRep.io")
    if s.get("_has_whoisxml"):
        sources.append("WhoisXML Reverse WHOIS")

    lines.append("## Raw intel")
    lines.append(f"Full JSON per source in `{raw_dir}/`. Sources: {', '.join(sources)}.")
    lines.append("")
    lines.append("> *Absence from public blocklists for campaigns <72h old is normal and is not exoneration.*")
    return "\n".join(lines)


# ---------- Main ----------

def main() -> int:
    ap = argparse.ArgumentParser(description="Passive URL triage (defensive OSINT).")
    ap.add_argument("url", help="URL to triage")
    ap.add_argument("--report-dir", default=None,
                    help="Where to write report + raw (default /tmp/url-triage-<ts>)")
    ap.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"))
    ap.add_argument("--otx-key", default=os.environ.get("OTX_API_KEY"))
    ap.add_argument("--urlhaus-key", default=os.environ.get("URLHAUS_API_KEY"))
    ap.add_argument("--threatfox-key", default=os.environ.get("THREATFOX_API_KEY"))
    ap.add_argument("--emailrep-key", default=os.environ.get("EMAILREP_API_KEY"))
    ap.add_argument("--pulsedive-key", default=os.environ.get("PULSEDIVE_API_KEY"))
    ap.add_argument("--whoisxml-key", default=os.environ.get("WHOISXML_API_KEY"))
    args = ap.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rdir = Path(args.report_dir or f"/tmp/url-triage-{ts}")
    raw = rdir / "raw"
    raw.mkdir(parents=True, exist_ok=True)

    parsed = parse_url(args.url)
    log(f"target apex={parsed['apex']} tld={parsed['tld']}")

    def save(name: str, obj: object) -> None:
        (raw / f"{name}.json").write_text(json.dumps(obj, indent=2, default=str))

    # ===== STAGE 1: Domain fingerprint — parallel =====
    log("Stage 1: DNS + RDAP + crt.sh (parallel) …")
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        f_dns  = ex.submit(dns_bundle, parsed["host"])
        f_rdap = ex.submit(rdap, parsed["apex"])
        f_crt  = ex.submit(crtsh, parsed["apex"])
        dns       = f_dns.result()
        rdap_data = f_rdap.result()
        crt       = f_crt.result()

    save("dns", dns)
    save("rdap", rdap_data)
    save("crtsh", crt[:50])

    # Derive Stage-1 signals
    ips = dns.get("A", []) + dns.get("AAAA", [])
    primary_ip = next((ip for ip in ips if "." in ip), None)  # prefer IPv4

    domain_registered: str | None = None
    registrar: str | None = None
    privacy_shield: str | None = None
    if isinstance(rdap_data, dict) and "_error" not in rdap_data:
        for ev in rdap_data.get("events", []) or []:
            if ev.get("eventAction") in ("registration", "last changed"):
                domain_registered = ev.get("eventDate", "")[:10]
                if ev.get("eventAction") == "registration":
                    break
        # Extract registrar name from entities
        for entity in rdap_data.get("entities", []) or []:
            if "registrar" in (entity.get("roles", []) or []):
                vcard = entity.get("vcardArray", [None, []])[1] if entity.get("vcardArray") else []
                for item in vcard:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        registrar = item[3]
                        break
        # Privacy shield detection
        rdap_str = json.dumps(rdap_data).lower()
        for shield in ["withheldforprivacy", "privacyguard", "domainprivacy", "whoisguard",
                       "perfect privacy", "contact privacy", "redacted for privacy"]:
            if shield in rdap_str:
                privacy_shield = shield
                break

    registrant_email = extract_rdap_email(rdap_data)

    cert_not_before: str | None = None
    cert_sha: str | None = None
    issuer: str | None = None
    if crt:
        try:
            not_befores = sorted(c.get("not_before", "") for c in crt if c.get("not_before"))
            cert_not_before = not_befores[0] if not_befores else None
            issuer = crt[0].get("issuer_name", "")
            cert_sha = crt[0].get("serial_number")
        except Exception:
            pass

    if not domain_registered and cert_not_before:
        domain_registered = cert_not_before[:10]

    age_days: int | None = None
    if domain_registered:
        try:
            age_days = (
                datetime.now(timezone.utc) -
                datetime.fromisoformat(domain_registered.replace("Z", "+00:00"))
                .replace(tzinfo=timezone.utc)
            ).days
        except Exception:
            pass

    # ===== STAGE 2: Threat intel + passive fetch — all parallel =====
    log("Stage 2: urlscan, VT, OTX, PhishStats, URLhaus, ThreatFox, OpenPhish, Pulsedive, fetch …")
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        f_us    = ex.submit(urlscan_search, f"domain:{parsed['apex']}")
        f_vt    = ex.submit(virustotal_domain, parsed["apex"], args.vt_key)
        f_otx   = ex.submit(otx_general, parsed["apex"], args.otx_key)
        f_ps    = ex.submit(phishstats, parsed["apex"])
        f_uh    = ex.submit(urlhaus, parsed["apex"], args.urlhaus_key)
        f_tf    = ex.submit(threatfox, parsed["apex"], args.threatfox_key)
        f_op    = ex.submit(openphish_check, args.url, parsed["apex"])
        f_pd    = ex.submit(pulsedive, parsed["apex"], args.pulsedive_key)
        f_fetch = ex.submit(passive_fetch, args.url)

        us1     = f_us.result()
        vt      = f_vt.result()
        otx     = f_otx.result()
        ps_data = f_ps.result()
        uh_data = f_uh.result()
        tf_data = f_tf.result()
        op_data = f_op.result()
        pd_data = f_pd.result()
        fetch   = f_fetch.result()

    save("urlscan_search", us1)
    save("virustotal", vt)
    save("otx", otx)
    save("phishstats", ps_data)
    save("urlhaus", uh_data)
    save("threatfox", tf_data)
    save("openphish", op_data)
    save("pulsedive", pd_data)
    save("passive_fetch", {k: v for k, v in fetch.items() if k != "probes"} | {
        "probes": [{kk: vv for kk, vv in p.items() if kk != "body_text"}
                   for p in fetch["probes"]]})

    # Fetch urlscan result detail for first result
    us_result: dict = {}
    if us1.get("results"):
        uuid = (us1["results"][0].get("_id") or
                us1["results"][0].get("task", {}).get("uuid"))
        if uuid:
            us_result = urlscan_result(uuid)
            save("urlscan_result", us_result)

    body_text = next(
        (p.get("body_text", "") for p in fetch["probes"] if p.get("body_text")), "")
    content = analyse_body(body_text)
    save("content", content)

    # ===== STAGE 3: IP-dependent lookups — parallel =====
    shodan_data: dict = {}
    co_hosted_domains: list[str] = []
    if primary_ip:
        log(f"Stage 3: Shodan InternetDB + HackerTarget reverse IP for {primary_ip} …")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            f_sh = ex.submit(shodan_internetdb, primary_ip)
            f_ht = ex.submit(hackertarget_reverse_ip, primary_ip)
            shodan_data      = f_sh.result()
            co_hosted_domains = f_ht.result()
        save("shodan", shodan_data)
        save("hackertarget_reverse_ip", co_hosted_domains)

    # ===== STAGE 4: Registrant email-dependent lookups — parallel =====
    erep_data: dict = {}
    whoisxml_data: dict = {}
    if registrant_email:
        log(f"Stage 4: EmailRep.io + WhoisXML for registrant {registrant_email} …")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            f_er = ex.submit(emailrep, registrant_email, args.emailrep_key)
            f_wx = ex.submit(whoisxml_reverse_whois, registrant_email, args.whoisxml_key)
            erep_data    = f_er.result()
            whoisxml_data = f_wx.result()
        save("emailrep", erep_data)
        save("whoisxml", whoisxml_data)

    # ===== Derive all signals =====

    # urlscan ML verdict
    us_ml = False
    if us_result:
        verdicts = us_result.get("verdicts", {})
        us_ml = bool(verdicts.get("engines", {}).get("malicious"))

    # VT
    vt_hits = 0
    vt_total = 0
    try:
        stats = vt["data"]["attributes"]["last_analysis_stats"]
        vt_hits = stats.get("malicious", 0)
        vt_total = sum(stats.values())
    except Exception:
        pass

    # OTX
    otx_pulses = 0
    try:
        otx_pulses = otx.get("pulse_info", {}).get("count", 0)
    except Exception:
        pass

    # PhishStats
    ps_score = 0.0
    ps_count = len(ps_data)
    if ps_data:
        try:
            ps_score = max(float(r.get("score", 0)) for r in ps_data if isinstance(r, dict))
        except Exception:
            pass

    # URLhaus
    urlhaus_hit = False
    urlhaus_url_count = 0
    if isinstance(uh_data, dict) and uh_data.get("query_status") == "is_host":
        urlhaus_url_count = uh_data.get("url_count", 0)
        urlhaus_hit = urlhaus_url_count > 0

    # ThreatFox
    threatfox_hit = False
    threatfox_malware = ""
    if isinstance(tf_data, dict) and tf_data.get("query_status") == "ok":
        iocs = tf_data.get("data") or []
        if iocs:
            threatfox_hit = True
            threatfox_malware = (
                iocs[0].get("malware", "") if isinstance(iocs[0], dict) else ""
            )

    # OpenPhish
    openphish_hit = op_data.get("in_feed", False)

    # Pulsedive
    pd_risk = ""
    if isinstance(pd_data, dict) and "_skipped" not in pd_data and "_error" not in pd_data:
        pd_risk = pd_data.get("risk", "")

    # Shodan — extract ASN info from hostnames + IP WHOIS
    shodan_vulns: list[str] = []
    shodan_suspicious_ports: list[int] = []
    shodan_hostnames: list[str] = []
    if isinstance(shodan_data, dict) and "_error" not in shodan_data and "_skipped" not in shodan_data:
        shodan_vulns = shodan_data.get("vulns", []) or []
        all_ports = shodan_data.get("ports", []) or []
        shodan_suspicious_ports = [p for p in all_ports if p in SUSPICIOUS_PORTS]
        shodan_hostnames = shodan_data.get("hostnames", []) or []

    co_hosted_count = len(co_hosted_domains)

    # IP WHOIS for ASN — lightweight query via RDAP for IP
    asn_name: str | None = None
    asn_country: str | None = None
    if primary_ip:
        try:
            code, _, body = http_get(
                f"https://rdap.arin.net/registry/ip/{primary_ip}",
                headers={"Accept": "application/rdap+json"}, timeout=10)
            if code == 200 and body:
                ip_rdap = json.loads(body)
                asn_name = ip_rdap.get("name", "")
                country_val = ip_rdap.get("country")
                if not country_val:
                    for ev in ip_rdap.get("entities", []):
                        vcard = ev.get("vcardArray", [None, []])[1] if ev.get("vcardArray") else []
                        for item in vcard:
                            if isinstance(item, list) and len(item) >= 4 and item[0] == "adr":
                                addr = item[3] if isinstance(item[3], dict) else {}
                                country_val = addr.get("label", "").split("\n")[-1] if isinstance(addr, dict) else ""
                asn_country = country_val
                save("ip_rdap", ip_rdap)
        except Exception:
            pass
    # Cloudflare detection (needed before ASN fallback)
    cloudflare = any(
        ("cloudflare" in (p.get("server") or "").lower()) or p.get("cf_ray")
        for p in fetch.get("probes", [])
    )
    if not cloudflare:
        for ns in dns.get("NS", []):
            if "cloudflare" in ns.lower():
                cloudflare = True
                break
    # Fallback: if Cloudflare, we know the ASN
    if not asn_name and cloudflare:
        asn_name = "AS13335 (Cloudflare)"

    # EmailRep
    emailrep_malicious = False
    emailrep_credentials_leaked = False
    if isinstance(erep_data, dict) and "_skipped" not in erep_data and "_error" not in erep_data:
        details = erep_data.get("details", {}) or {}
        emailrep_malicious = bool(details.get("malicious_activity"))
        emailrep_credentials_leaked = bool(details.get("credentials_leaked"))

    # WhoisXML
    whoisxml_domain_count = 0
    if isinstance(whoisxml_data, dict) and "_skipped" not in whoisxml_data:
        whoisxml_domain_count = whoisxml_data.get("domainsCount", 0)

    # Cloaking
    statuses = {p["ua"]: p["status"] for p in fetch["probes"]}
    cloaking = len({sv for sv in statuses.values() if sv != 0}) > 1

    letsencrypt = bool(issuer and "let's encrypt" in issuer.lower()) or (
        issuer in ("E1", "E2", "E5", "E6", "E7", "E8", "R3", "R10", "R11"))

    brand_imp: str | None = None
    if content.get("brands"):
        brand_imp = content["brands"][0]
    for b in BRAND_KEYWORDS:
        if b in parsed["apex"].lower() and b != parsed["apex"].split(".")[0]:
            brand_imp = brand_imp or b

    page_sha = next((p.get("sha256") for p in fetch["probes"] if p.get("sha256")), None)

    signals = {
        # Core
        "url":              parsed["url"],
        "apex":             parsed["apex"],
        "tld":              parsed["tld"],
        "path_segments":    parsed["path_segments"],
        "domain_registered": domain_registered,
        "domain_age_days":  age_days,
        "asn":              asn_name,
        "asn_country":      asn_country,
        "ips":              ips,
        "cloudflare":       cloudflare,
        "letsencrypt":      letsencrypt,
        "cert_sha256":      cert_sha,
        "page_sha256":      page_sha,
        "cloaking":         cloaking,
        "probes":           fetch["probes"],
        # Threat intel
        "urlscan_ml_malicious":   us_ml,
        "vt_malicious_engines":   vt_hits,
        "vt_total_engines":       vt_total,
        "otx_pulses":             otx_pulses,
        # Content
        "brand_impersonation":    brand_imp,
        "has_password_input":     content.get("has_password_input", False),
        "crypto_addresses":       content.get("crypto_addresses", {}),
        "language":               content.get("lang"),
        # Registrant
        "registrant_email":       registrant_email,
        "registrar":              registrar,
        "privacy_shield":         privacy_shield,
        # New intel
        "phishstats_score":       ps_score,
        "phishstats_count":       ps_count,
        "urlhaus_hit":            urlhaus_hit,
        "urlhaus_url_count":      urlhaus_url_count,
        "threatfox_hit":          threatfox_hit,
        "threatfox_malware":      threatfox_malware,
        "openphish_hit":          openphish_hit,
        "pulsedive_risk":         pd_risk,
        # Infrastructure
        "shodan_data":            shodan_data,
        "shodan_vulns":           shodan_vulns,
        "shodan_suspicious_ports": shodan_suspicious_ports,
        "co_hosted_domains":      co_hosted_domains[:20],
        "co_hosted_count":        co_hosted_count,
        # EmailRep
        "emailrep_data":              erep_data,
        "emailrep_malicious":         emailrep_malicious,
        "emailrep_credentials_leaked": emailrep_credentials_leaked,
        # WhoisXML
        "whoisxml_domain_count":  whoisxml_domain_count,
        # Meta
        "date":         datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "_has_vt":      bool(args.vt_key),
        "_has_otx":     bool(args.otx_key),
        "_has_pulsedive": bool(args.pulsedive_key),
        "_has_emailrep":  bool(args.emailrep_key),
        "_has_whoisxml":  bool(args.whoisxml_key),
    }

    sc, fired = score(signals)
    signals["score"] = sc
    signals["fired"] = fired
    signals["verdict"] = verdict(sc)
    signals["classification"] = classify(sc, signals)

    # TL;DR
    if sc >= 70:
        tldr = (f"High-confidence scam. Domain `{defang(parsed['apex'])}` was registered "
                f"{age_days if age_days is not None else '?'} days ago and shows "
                f"{len(fired)} malicious indicators. Do not interact.")
    elif sc >= 40:
        tldr = (f"Likely scam. Several indicators fired ({len(fired)}). "
                f"Treat as malicious until proven otherwise.")
    elif sc >= 15:
        tldr = "Suspicious but not conclusive. Avoid interaction, monitor blocklists."
    else:
        tldr = ("Insufficient evidence to call malicious. If the URL arrived unsolicited, "
                "still avoid clicking — new scams evade detection for ~72h.")
    signals["tldr"] = tldr

    save("signals", signals)

    md = render_report(signals, raw)
    report_path = rdir / "report.md"
    report_path.write_text(md)

    # Stdout = JSON (for programmatic use) + separator + markdown report
    print(json.dumps(signals, indent=2, default=str))
    print("\n---\n")
    print(md)
    print(f"\n[report saved to {report_path}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
