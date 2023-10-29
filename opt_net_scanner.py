#!/usr/bin/env python
# ------author Samuel Bonu


#network scanner using optparse

import scapy.all as scapy
import os
import optparse

# Broadcast MAC address
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def get_argument():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip_addr", help="specify a target or range")
    (options, arguments) = parser.parse_args()
    return options 


def scan(ip_addr):
    request_ARP = scapy.ARP(pdst=ip_addr)

    broAdcast = scapy.Ether(dst=BROADCAST_MAC)

    packet_arp = broAdcast/request_ARP

    received_lst = scapy.srp(packet_arp, timeout=1)[0]
    client_lst = []
    for cli in received_lst:
        client_dict = {'ip': cli[1].psrc, 'mac': cli[1].hwsrc}
        client_lst.append(client_dict)
    return client_lst


def main():
    options = get_argument()
    try:
        if options.ip_addr:
            scan_result = scan(options.ip_addr)
            print('IP addr\t\t\tMac addr\n-------------------------------------')
            for client in scan_result:
                print(client['ip'] + '\t||   ' + client['mac'])
        else:
            print('[-] Please specify a target IP address or range using the -t or --target option.')
    except KeyboardInterrupt:
        print(f'[=] Program interrupted by user')


# Check if running as root
if __name__ == "__main__":
    if os.getuid() == 0:
        main()
    else:
        print('[-] Run the program as root')
