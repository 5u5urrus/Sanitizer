"""
Author: Vahe Demirkhanyan
Usage:
    python sanitizer.py <input string or file path>
    python sanitizer.py -f <file path> (for advanced parsing of files to scrape for IPs/URLs)>

Description:
    - Accepts either direct string input or file input (-f).
    - Identifies IP addresses, IP ranges, CIDR notations, and domains/URLs.
    - Expands valid IP ranges and CIDRs (except invalid /0).
    - Sorts final output numerically (IPs) then alphabetically (domains).
"""

import ipaddress
import re
import sys
import os
from itertools import product

def extract_targets_from_text(text):
    targets = set()
    text = re.sub(r'(\d{1,3}(?:\.\d{1,3}){3})\s*/\s*(\d{1,2})', r'\1/\2', text)
    cidr_pattern = r'\b((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})\b'
    for cidr in re.findall(cidr_pattern, text):
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.prefixlen == 0:
                print(f"Warning: Skipping invalid CIDR: {cidr}")
                continue
            for ip in network.hosts():
                targets.add(str(ip))
        except ValueError:
            continue

    ip_range_full_pattern = r'\b(((?:\d{1,3}\.){3}\d{1,3}))-(((?:\d{1,3}\.){3}\d{1,3}))\b'
    for full_range in re.findall(ip_range_full_pattern, text):
        start_ip = full_range[1]
        end_ip = full_range[3]
        try:
            start_addr = ipaddress.IPv4Address(start_ip)
            end_addr = ipaddress.IPv4Address(end_ip)
            if int(start_addr) <= int(end_addr):
                for ip_int in range(int(start_addr), int(end_addr) + 1):
                    targets.add(str(ipaddress.IPv4Address(ip_int)))
        except ipaddress.AddressValueError:
            continue

    ip_range_general_pattern = r'\b(?=\d{1,3}(?:-\d{1,3})?(?:\.\d{1,3}(?:-\d{1,3})?){3})(\d{1,3}(?:-\d{1,3})?(?:\.\d{1,3}(?:-\d{1,3})?){3})\b'
    for ip_range in re.findall(ip_range_general_pattern, text):
        if '-' not in ip_range:
            continue
        segments = ip_range.split('.')
        if len(segments) != 4:
            continue
        try:
            octet_ranges = []
            for seg in segments:
                if '-' in seg:
                    bounds = seg.split('-')
                    if len(bounds) != 2:
                        octet_ranges = None
                        break
                    start, end = int(bounds[0]), int(bounds[1])
                    if start > end:
                        octet_ranges = None
                        break
                    octet_ranges.append(range(start, end + 1))
                else:
                    octet_ranges.append([int(seg)])
            if octet_ranges is None:
                continue
            for ip_tuple in product(*octet_ranges):
                ip_str = '.'.join(map(str, ip_tuple))
                try:
                    ipaddress.IPv4Address(ip_str)
                    targets.add(str(ip_str))
                except ipaddress.AddressValueError:
                    continue
        except ValueError:
            continue

    #ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'

    for ip in re.findall(ip_pattern, text):
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            targets.add(str(ip_obj))
        except ipaddress.AddressValueError:
            continue

    # domain_pattern = r'(?<![\w/])(?:https?://)?(?:www\.)?((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?=\s|$|[.,;:])'
    domain_pattern = r'(?<![\w/])(?:https?://)?(?:www\.)?((?:[a-zA-Z0-9_-]+\.)+[a-zA-Z0-9-]{2,})(?=\s|$|[^a-zA-Z0-9_-])'
    for domain in re.findall(domain_pattern, text):
        if domain:
            targets.add(domain)

    return list(targets)

def parse_input(input_string):
    results = []
    parts = input_string.split()

    for part in parts:
        part = re.sub(r'^(http://|https://|//)', '', part)
        if '/' in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
                if network.prefixlen == 0:
                    print(f"Warning: Skipping invalid CIDR: {part}")
                    continue
                results.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                if '.' in part:
                    domain = part.split('/')[0]
                    results.append(domain)
                else:
                    print(f"Invalid CIDR notation: {part}")
        elif '-' in part:
            m = re.match(r'^(((?:\d{1,3}\.){3}\d{1,3}))-(((?:\d{1,3}\.){3}\d{1,3}))$', part)
            if m:
                start_ip, end_ip = m.group(2), m.group(4)
                try:
                    start_addr = ipaddress.IPv4Address(start_ip)
                    end_addr = ipaddress.IPv4Address(end_ip)
                    for ip_int in range(int(start_addr), int(end_addr) + 1):
                        results.append(str(ipaddress.IPv4Address(ip_int)))
                except ipaddress.AddressValueError:
                    print(f"Invalid IP range: {part}")
                continue

            m = re.match(r'^((?:\d{1,3}\.){3})(\d{1,3})-(\d{1,3})$', part)
            if m:
                base, start_str, end_str = m.groups()
                try:
                    start_val = int(start_str)
                    end_val = int(end_str)
                    for i in range(start_val, end_val + 1):
                        candidate = base + str(i)
                        ipaddress.IPv4Address(candidate)
                        results.append(candidate)
                except (ValueError, ipaddress.AddressValueError):
                    print(f"Invalid IP range: {part}")
                continue

            segments = part.split('.')
            if len(segments) == 4:
                try:
                    octet_ranges = []
                    for seg in segments:
                        if '-' in seg:
                            bounds = seg.split('-')
                            if len(bounds) != 2:
                                octet_ranges = None
                                break
                            start, end = int(bounds[0]), int(bounds[1])
                            if start > end:
                                octet_ranges = None
                                break
                            octet_ranges.append(range(start, end + 1))
                        else:
                            octet_ranges.append([int(seg)])
                    if octet_ranges is not None:
                        for ip_tuple in product(*octet_ranges):
                            ip_str = '.'.join(map(str, ip_tuple))
                            try:
                                ipaddress.IPv4Address(ip_str)
                                results.append(ip_str)
                            except ipaddress.AddressValueError:
                                continue
                        continue
                    else:
                        print(f"Unrecognized range format: {part}")
                except ValueError:
                    print(f"Invalid IP range: {part}")
                    continue
            else:
                print(f"Unrecognized range format: {part}")
        elif all(c.isdigit() or c == '.' for c in part):
            try:
                ip = ipaddress.ip_address(part)
                results.append(str(ip))
            except ValueError:
                print(f"Invalid IP address: {part}")
        else:
            domain = part.split('/')[0]
            results.append(domain)

    return results

def sort_targets(targets):
    ips = []
    domains = []
    for target in targets:
        try:
            ipaddress.IPv4Address(target)
            ips.append(target)
        except ipaddress.AddressValueError:
            domains.append(target)
    sorted_ips = sorted(ips, key=lambda ip: int(ipaddress.IPv4Address(ip)))
    sorted_domains = sorted(domains, key=str.lower)
    return sorted_ips + sorted_domains

def read_input_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        return file.read()

def main():
    if len(sys.argv) < 2:
        print("Usage: python sanitizer.py <input string or file path>")
        print("       python sanitizer.py -f <file path> (to scan file for IPs/URLs)")
        return

    if sys.argv[1] == '-f' and len(sys.argv) > 2:
        file_path = sys.argv[2]
        if not os.path.isfile(file_path):
            print(f"Error: File '{file_path}' not found")
            return
        content = read_input_from_file(file_path)
        results = extract_targets_from_text(content)
    else:
        if os.path.isfile(sys.argv[1]):
            input_string = read_input_from_file(sys.argv[1])
            results = parse_input(input_string)
        else:
            input_string = ' '.join(sys.argv[1:])
            results = parse_input(input_string)

    sorted_results = sort_targets(results)
    for result in sorted_results:
        print(result)

if __name__ == "__main__":
    main()
