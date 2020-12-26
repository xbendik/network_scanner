#!usr/bin/env python

#import scapy.all as scapy
from scapy.layers import all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    clients_list = []
    for row in answered_list:
        clients_row = {"ip": row[1].psrc, "mac": row[1].hwsrc}
        clients_list.append(clients_row)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC address\n-----------------------------------------")
    for row in results_list:
        print(row["ip"] + "\t\t" + row["mac"])

scan_result = scan("192.168.1.1/24")
print_result(scan_result)
