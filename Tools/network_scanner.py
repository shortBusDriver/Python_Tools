#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", dest="scan", help=" Add IP scan range EG-0.0.0.0/24 to get MACs")
    (options,arguments) = parser.parse_args()
    if not options.scan:
        parser.error("[-] Please specify a valid IP, use --help for more info")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    print("IP\t\t\tMAC Address\n -----------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)


options = get_arguments()

current_scan = scan(options.scan)
