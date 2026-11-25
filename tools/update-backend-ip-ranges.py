#!/usr/bin/env python3
"""Regenerate apps/origin-trace-backend/assets/backend-ip-ranges.json.

The backend map (docs/product/backend-map-v1.md) attributes a captured remote
address to a provider only from these published lists, bundled so that a
reading never looks anything up. This maintenance tool is the only part that
touches the network, and only when a maintainer runs it. With --input-dir it
reads previously downloaded copies instead, named by the SOURCES keys below.

The output is deterministic for the same inputs: prefixes are collapsed and
sorted, and the retrieval date comes from the lists' own timestamps when they
carry one.
"""
import argparse
import ipaddress
import json
import pathlib
import sys
import urllib.request

SOURCES = {
    "cloudflare-v4": "https://www.cloudflare.com/ips-v4",
    "cloudflare-v6": "https://www.cloudflare.com/ips-v6",
    "fastly": "https://api.fastly.com/public-ip-list",
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "gcp": "https://www.gstatic.com/ipranges/cloud.json",
    "google": "https://www.gstatic.com/ipranges/goog.json",
}
OUTPUT = pathlib.Path(__file__).resolve().parent.parent / "apps/origin-trace-backend/assets/backend-ip-ranges.json"


def read(name, input_dir):
    if input_dir:
        return (input_dir / name).read_bytes()
    request = urllib.request.Request(SOURCES[name], headers={"User-Agent": "origin-trace-range-update"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise SystemExit(f"{SOURCES[name]} answered {response.status}")
        return response.read()


def collapse(prefixes):
    networks = [ipaddress.ip_network(prefix.strip()) for prefix in prefixes if prefix.strip()]
    v4 = ipaddress.collapse_addresses(n for n in networks if n.version == 4)
    v6 = ipaddress.collapse_addresses(n for n in networks if n.version == 6)
    return [str(n) for n in sorted(v4)] + [str(n) for n in sorted(v6)]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input-dir", type=pathlib.Path, help="read downloaded lists from this directory")
    parser.add_argument("--output", type=pathlib.Path, default=OUTPUT)
    args = parser.parse_args()

    text = {name: read(name, args.input_dir) for name in SOURCES}
    aws = json.loads(text["aws"])
    gcp = json.loads(text["gcp"])
    google = json.loads(text["google"])

    def aws_service(service):
        return [p["ip_prefix"] for p in aws["prefixes"] if p["service"] == service] + [
            p["ipv6_prefix"] for p in aws["ipv6_prefixes"] if p["service"] == service
        ]

    def google_prefixes(document):
        return [p.get("ipv4Prefix") or p.get("ipv6Prefix") for p in document["prefixes"]]

    providers = [
        {
            "id": "cloudflare",
            "name": "Cloudflare",
            "sources": [SOURCES["cloudflare-v4"], SOURCES["cloudflare-v6"]],
            "prefixes": collapse(text["cloudflare-v4"].decode().split() + text["cloudflare-v6"].decode().split()),
        },
        {
            "id": "fastly",
            "name": "Fastly",
            "sources": [SOURCES["fastly"]],
            "prefixes": collapse(
                json.loads(text["fastly"])["addresses"] + json.loads(text["fastly"]).get("ipv6_addresses", [])
            ),
        },
        {
            "id": "cloudfront",
            "name": "Amazon CloudFront",
            "sources": [SOURCES["aws"] + " (service CLOUDFRONT)"],
            "prefixes": collapse(aws_service("CLOUDFRONT")),
        },
        {
            "id": "aws",
            "name": "Amazon Web Services",
            "sources": [SOURCES["aws"] + " (service AMAZON)"],
            "prefixes": collapse(aws_service("AMAZON")),
        },
        {
            "id": "gcp",
            "name": "Google Cloud",
            "sources": [SOURCES["gcp"]],
            "prefixes": collapse(google_prefixes(gcp)),
        },
        {
            "id": "google",
            "name": "Google",
            "sources": [SOURCES["google"]],
            "prefixes": collapse(google_prefixes(google)),
        },
    ]
    retrieved = aws["createDate"][:10]
    document = {"format": "reb-backend-ip-ranges-v1", "retrieved": retrieved, "providers": providers}
    args.output.write_text(json.dumps(document, indent=1) + "\n")
    counts = ", ".join(f"{p['id']} {len(p['prefixes'])}" for p in providers)
    print(f"wrote {args.output.name}: {counts}")


if __name__ == "__main__":
    sys.exit(main())
