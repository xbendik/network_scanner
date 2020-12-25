#!usr/bin/env python

import scapy.all as scapy

def scan(ip):
    scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    print(arp_request_broadcast.summary())

    arp_request_broadcast.show()

scan("192.168.108.1/24")

