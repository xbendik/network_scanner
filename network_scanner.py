#!usr/bin/env python
#run it in Python 3!

from scapy.layers import all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/IP range for scanning. For example: -t 192.168.1.1/24")
    parser.add_argument("-to", "--timeout", dest="timeout", help="Timeout in seconds for response on one client. For example: -to 3 ")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify target, for example: -t 192.168.1.1/24. Use --help for more info.")
    if not options.timeout:
        parser.error("[-] Please specify timeout in seconds, for example: -to 3. Use --help for more info.")
    return options

def scan(ip, timeout):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=timeout, verbose=False)[0]

    clients_list = []
    for row in answered_list:
        clients_row = {"ip": row[1].psrc, "mac": row[1].hwsrc}
        clients_list.append(clients_row)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC address\n-----------------------------------------")
    for row in results_list:
        print(row["ip"] + "\t\t" + row["mac"])

options = get_arguments()
timeout = int(options.timeout)
print("[+] Starting scan ")
print("[+] Scanning... ")
scan_result = scan(options.target, timeout)
print_result(scan_result)
print("[+] Done!")