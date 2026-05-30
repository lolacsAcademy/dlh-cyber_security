#!/usr/bin/env python3

dns_resolver = __import__("0-dns_resolver").resolve_domain_to_ipv4


test_domains = [
    "holbertonschool.com",
    "google.com",
    "github.com",
    "example.com",
    "this-is-not-a-site.com",
]

print("DNS Resolver Test")
print("=" * 60)

for domain in test_domains:
    result = dns_resolver(domain)
    if result:
        print(f"{domain:40} -> {result}")
    else:
        print(f"{domain:40} -> Failed to resolve")

print("=" * 60)
