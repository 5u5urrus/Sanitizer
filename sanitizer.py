import ipaddress
import sys
import re
import os
from itertools import product

def parse_input(input_string):
    results = []
    parts = input_string.split()
    for part in parts:
        # Normalize URLs by removing http://, https://, and leading //
        part = re.sub(r'^(http://|https://|//)', '', part)

        if '/' in part:
            #Handle CIDR notation
            try:
                network = ipaddress.ip_network(part, strict=False)
                results.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                print(f"Invalid CIDR notation: {part}")
        elif '-' in part:
            #Handle complex IP ranges 
            try:
                segments = part.split('.')
                range_segments = [segment.split('-') for segment in segments]
                #generate all combinations within the specified ranges
                ip_ranges = [range(int(seg[0]), int(seg[1])+1) if len(seg) > 1 else [int(seg[0])] for seg in range_segments]
                for ip_tuple in product(*ip_ranges):
                    ip_address = '.'.join(map(str, ip_tuple))
                    results.append(ip_address)
            except ValueError:
                print(f"Invalid IP range: {part}")
        elif all(c.isdigit() or c == '.' for c in part):
            #Handle individual IP addresses
            try:
                ip = ipaddress.ip_address(part)
                results.append(str(ip))
            except ValueError:
                print(f"Invalid IP address: {part}")
        else:
            #when it's just a domain name
            domain = part.split('/')[0]
            results.append(domain)

    return results


def read_input_from_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        return ' '.join(line.strip() for line in lines if line.strip())

def main():
    if os.path.isfile(sys.argv[1]):
        input_string = read_input_from_file(sys.argv[1])
    else:
        input_string = ' '.join(sys.argv[1:])

    results = parse_input(input_string)
    for result in results:
        print(result)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main()
    else:
        print("Usage: python sanitizer.py <input string or file path>")
