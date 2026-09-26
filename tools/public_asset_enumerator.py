#!/usr/bin/env python3
import argparse
import json

import dns.resolver
import requests


def fetch_crtsh(domain: str, limit: int = 200):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        items = []
        seen = set()
        for row in data:
            name = row.get("name_value")
            if not name:
                continue
            for sub in name.split("\n"):
                sub = sub.strip()
                if sub and sub not in seen:
                    seen.add(sub)
                    items.append(sub)
                if len(items) >= limit:
                    return items
        return items
    except Exception as exc:
        return {"error": str(exc)}


def resolve_a_records(domain: str):
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.resolve(domain, "A")
        return [str(item) for item in answers]
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(description="Enumerate public subdomains for authorized asset mapping.")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--limit", type=int, default=200, help="Maximum subdomains to display")
    args = parser.parse_args()

    result = fetch_crtsh(args.domain, args.limit)
    if isinstance(result, dict) and "error" in result:
        print(f"ERROR: {result['error']}")
        return

    unique_sites = []
    for name in result:
        if name in unique_sites:
            continue
        unique_sites.append(name)

    print(f"Public subdomains for {args.domain} ({len(unique_sites)})")
    for sub in unique_sites:
        try:
            ips = resolve_a_records(sub)
            if ips:
                print(f"{sub} -> {ips}")
            else:
                print(sub)
        except Exception:
            print(sub)


if __name__ == "__main__":
    main()
