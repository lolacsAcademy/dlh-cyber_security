#!/usr/bin/env python3

import sys
dns_records = __import__("1-dns_records").query_dns_records


if len(sys.argv) != 2:
    print("Usage: python3 1-main.py ")
    sys.exit(1)

domain_name = sys.argv[1]
results = dns_records(domain_name)

print("=" * 70)
print(f"DNS Record Enumeration: {domain_name}")
print("=" * 70)
print()

found_record_types = []
total_records = 0

record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
for record_type in record_types:
    if record_type in results:
        answers = results[record_type]
        answer_list = list(answers)
        count = len(answer_list)
        found_record_types.append(record_type)
        total_records += count

        print(f"{record_type} Records ({count}):")

        if record_type == 'MX':
            for answer in answer_list:
                print(f"  • {answer.preference} {answer.exchange}")
        elif record_type == 'SOA':
            for answer in answer_list:
                soa = answer
                print(f"  • Primary: {soa.mname}, Admin: {soa.rname}, Serial: {soa.serial}")
        elif record_type == 'TXT':
            for answer in answer_list:
                for txt_string in answer.strings:
                    decoded = txt_string.decode().strip('"')
                    print(f"  • \"{decoded}\"")
        else:
            for answer in answer_list:
                print(f"  • {answer}")
        print()

print("=" * 70)
print(f"Summary: Found {len(found_record_types)} record types with {total_records} total records")
print("=" * 70)
print()
