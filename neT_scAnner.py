#!/usr/bin/env python
# ------author Samuel Bonu

#network scanner using argparse

import scapy.all as scapy
import os
import argparse

# Broadcast MAC address
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def scan(ip_addr):
    """Create ARP request packet
    pdst is the field containing the IP we want to specify"""
    request_ARP = scapy.ARP(pdst=ip_addr)

    """Create Ethernet frame with the destination MAC address set to broadcast
    dst is the field containing the broadcast MAC address"""
    broadcAst = scapy.Ether(dst=BROADCAST_MAC)

    # Create a packet (to send) which contains both the ARP request and destination address (broadcast address)
    packet_arp = broadcAst/request_ARP

    """packet_arp.show() --show summary for packet_arp
    send packet...recieved= those who has ip will repond, un_recieved are the ip that didn't respond"""
    
    received_lst = scapy.srp(packet_arp, timeout=1)[0] #it's a list of two element,the first is the answered
    client_lst = []
    for cli in received_lst:
        client_dict = {'ip': cli[1].psrc, 'mac': cli[1].hwsrc}
        client_lst.append(client_dict)
    return client_lst

def main():
    parser = argparse.ArgumentParser(description='Scan clients on your network')
    parser.add_argument('-t', '--target', dest='ip_addr', help='specify ip range')
    args = parser.parse_args()
    if not args.ip_addr:
        parser.error('[-] Error: ip range was not specified')
    try:
        scan_result = scan(args.ip_addr)  
        for client in scan_result:
            print('IP addr\t\t\tMac addr\n-------------------------------------')
            print(client['ip'] +'\t||   ' + client['mac'])
    except KeyboardInterrupt:
        print(f'[=] program interrupted by user')

    


# Check if running as root
if __name__ == "__main__":
    if os.getuid() == 0:
        main()
    else:
        print('[-] Run the program as root')
