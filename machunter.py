from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import argparse
import ipaddress
import asyncio
import re

def is_ip(ip):
    """Check if input is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_ip_list(ip_range):
    """Convert CIDR notation or range into a list of IPs."""
    ip_list = []

    # Handle CIDR notation (e.g., 192.168.1.0/24)
    if '/' in ip_range:
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []

    # Handle dash range (e.g., 10.1.86.15-100)
    dash_match = re.match(r"(\d+\.\d+\.\d+)\.(\d+)-(\d+)", ip_range)
    if dash_match:
        base_ip, start, end = dash_match.groups()
        start, end = int(start), int(end)
        if start <= end <= 255:  # Ensure valid range
            ip_list = [f"{base_ip}.{i}" for i in range(start, end + 1)]
            return ip_list

    # Invalid range
    return []

async def get_mac_async(ip):
    """Send ARP request asynchronously to get MAC address."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_mac, ip)

def get_mac(ip):
    """Send an ARP request to get the MAC address of a target IP."""
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    response, _ = srp(ether / arp_request, timeout=2, verbose=False)
    for _, received in response:
        return received.hwsrc
    return None

async def scan_network(ip_list):
    """Scan a list of IP addresses asynchronously."""
    tasks = [get_mac_async(ip) for ip in ip_list]
    results = await asyncio.gather(*tasks)

    for ip, mac in zip(ip_list, results):
        if mac:
            print(f"[+] {ip} → {mac}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="machunter.py",
        epilog="Mac Address Hunter in a Network",
        usage="machunter.py -ip <ip_address> OR -ipr <ip_range>",
        prefix_chars='-',
        add_help=True
    )

    parser.add_argument("-ip", "--ip-address", action="store", metavar="Target_IP", type=str,
                        help="Target IP.\tExample: 192.168.1.1")

    parser.add_argument("-ipr", "--ip-range", action="store", metavar="Target_IP_range", type=str,
                        help="Target IP range (CIDR or Dash).\tExample: 192.168.1.0/24 OR 10.1.86.15-100")

    parser.add_argument("-v", "--version", action="version", version="MAC Hunter v0.3", help="Print version information")

    args = parser.parse_args()

    if not args.ip_address and not args.ip_range:
        print("[!] You must specify an IP address or an IP range.")
        exit(1)

    if args.ip_address:
        mac = get_mac(args.ip_address)
        if mac:
            print(f"[+] MAC Address for {args.ip_address}: {mac}")
        else:
            print(f"[-] MAC Address not found for {args.ip_address}")

    if args.ip_range:
        ip_list = get_ip_list(args.ip_range)
        if ip_list:
            print(f"[*] Scanning {len(ip_list)} IPs in range {args.ip_range}...")
            asyncio.run(scan_network(ip_list))
        else:
            print("[!] Invalid IP range provided.")
