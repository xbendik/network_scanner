#!usr/bin/env python

#import scapy.all as scapy
from scapy.layers import all as scapy


def scan(ip):
    #scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1)
    print(answered_list.summary())

scan("192.168.1.1/24")

