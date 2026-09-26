#!/usr/bin/env python3
import argparse
import json
import socket
import ssl
import subprocess
from datetime import datetime
from urllib.parse import urlparse

import dns.resolver
import requests


def fetch_dns_records(domain: str):
    resolver = dns.resolver.Resolver()
    types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]
    results = {}
    for rtype in types:
        try:
            answers = resolver.resolve(domain, rtype)
            results[rtype] = [str(item) for item in answers]
        except Exception:
            results[rtype] = []
    return results


def fetch_crtsh_subdomains(domain: str, limit: int = 50):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        names = []
        seen = set()
        for item in data[:limit]:
            name = item.get("name_value")
            if not name:
                continue
            for sub in name.split("\n"):
                sub = sub.strip()
                if sub and sub not in seen:
                    seen.add(sub)
                    names.append(sub)
        return names
    except Exception as exc:
        return {"error": str(exc)}


def whois_lookup(domain: str):
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=20)
        return result.stdout.strip() or result.stderr.strip()
    except Exception as exc:
        return f"WHOIS unavailable: {exc}"


def fetch_http_headers(url: str):
    try:
        resp = requests.get(url, timeout=15, allow_redirects=True)
        return {
            "status": resp.status_code,
            "server": resp.headers.get("Server"),
            "via": resp.headers.get("Via"),
            "x_powered_by": resp.headers.get("X-Powered-By"),
            "content_type": resp.headers.get("Content-Type"),
            "final_url": resp.url,
        }
    except Exception as exc:
        return {"error": str(exc)}


def ssl_expiry(hostname: str, port: int = 443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"error": "No certificate returned"}
                not_after = cert.get("notAfter")
                if not_after:
                    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    return {
                        "issuer": cert.get("issuer"),
                        "subject": cert.get("subject"),
                        "notAfter": not_after,
                        "expires": expires.isoformat(),
                    }
        return {"error": "Certificate not available"}
    except Exception as exc:
        return {"error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description="Domain Intelligence for authorized public-sector and cyber security use.")
    parser.add_argument("domain", help="Domain or host to analyze")
    parser.add_argument("--url", help="Full URL to test headers, default: https://<domain>")
    parser.add_argument("--limit", type=int, default=20, help="Limit for public subdomains from crt.sh")
    args = parser.parse_args()

    domain = args.domain.strip().lower()
    url = args.url or f"https://{domain}"
    parsed = urlparse(url)
    host = parsed.netloc or domain

    print(f"[+] Domain: {domain}")
    print(f"[+] URL: {url}")
    print("=" * 60)

    print("[DNS Records]")
    dns_records = fetch_dns_records(domain)
    for rtype, values in dns_records.items():
        print(f"  {rtype}: {values if values else 'NONE'}")

    print("\n[Public Subdomains (crt.sh)]")
    subdomains = fetch_crtsh_subdomains(domain, limit=args.limit)
    if isinstance(subdomains, dict) and "error" in subdomains:
        print(f"  ERROR: {subdomains['error']}")
    else:
        for sub in subdomains[:args.limit]:
            print(f"  - {sub}")

    print("\n[WHOIS]")
    print(whois_lookup(domain)[:2000])

    print("\n[HTTP Headers]")
    headers = fetch_http_headers(url)
    print(json.dumps(headers, indent=2, default=str))

    print("\n[TLS Certificate]")
    ssl_info = ssl_expiry(host.split(":")[0])
    print(json.dumps(ssl_info, indent=2, default=str))


if __name__ == "__main__":
    main()
