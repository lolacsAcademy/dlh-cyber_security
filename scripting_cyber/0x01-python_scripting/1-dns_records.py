#!/usr/bin/env python3
import dns.resolver


def query_dns_records(domain_name):
    """Queries multiple DNS record types for a given domain."""
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            results[record_type] = answers
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoNameservers:
            pass
    return results


if __name__ == "__main__":
    pass
