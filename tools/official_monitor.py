#!/usr/bin/env python3
import argparse
import hashlib
import os
from datetime import datetime

import requests


def fetch_page(url: str):
    headers = {"User-Agent": "OSINT-Official-Monitor/1.0"}
    resp = requests.get(url, timeout=20, headers=headers)
    resp.raise_for_status()
    return resp.text


def save_snapshot(path: str, content: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def sha256_text(text: str):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser(description="Monitor a public official page for content changes.")
    parser.add_argument("--url", required=True, help="URL of the public official page")
    parser.add_argument("--keyword", help="Optional keyword to search in the page")
    parser.add_argument("--snapshot-dir", default=".snapshots", help="Directory for snapshots")
    args = parser.parse_args()

    os.makedirs(args.snapshot_dir, exist_ok=True)
    page = fetch_page(args.url)

    if args.keyword:
        found = args.keyword.lower() in page.lower()
        print(f"Keyword '{args.keyword}' found: {found}")

    filename = f"{hashlib.md5(args.url.encode()).hexdigest()}.txt"
    path = os.path.join(args.snapshot_dir, filename)

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            previous = f.read()
        current_hash = sha256_text(page)
        prev_hash = sha256_text(previous)
        print(f"Current hash: {current_hash}")
        print(f"Previous hash: {prev_hash}")
        print(f"Changed: {current_hash != prev_hash}")
    else:
        print("Snapshot not found. Creating initial snapshot.")

    save_snapshot(path, page)
    print(f"Snapshot saved to {path}")


if __name__ == "__main__":
    main()
