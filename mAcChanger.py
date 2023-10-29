#!/usr/bin/env python
# ------author Samuel Bonu
import os
import subprocess
import re
import argparse
import sys

def is_valid_mac(mac_addr):
    # Use a regular expression to validate the MAC address format
    mac_pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'# or use \w\w:\w\w:\w\w:\w\w:\w\w:\w\w
    return bool(re.match(mac_pattern, mac_addr))

def is_valid_interface(_interface):
    # use regex to validate interface
    interface_pattern = r'^(eth|wlan)[0-9]$'
    return bool(re.match(interface_pattern,_interface ))

def change_mac(nEt_interface, mAc_addr):
    
    try:
        if nEt_interface == 'docker0':
            print('[:] Warning, Do not use script to change docker0 mac addr ')
            sys.exit(1)

        if not is_valid_interface(nEt_interface):
            print(f'[-] specified interface is not recognized or does not support mac addr: {nEt_interface}')
            sys.exit(1)
            
        if not is_valid_mac(mAc_addr):
            print(f'[-] Invalid MAC address specified: {mAc_addr}')
            return

        # Disable the interface
        subprocess.run(["sudo", "ifconfig", nEt_interface, "down"], check=True)
        
        # Change the MAC address
        subprocess.run(["sudo", "ifconfig", nEt_interface, "hw", "ether", mAc_addr], check=True)
        
        # Enable the interface
        subprocess.run(["sudo", "ifconfig", nEt_interface, "up"], check=True)
        
        subprocess.check_output(["ifconfig", nEt_interface],)
        
        print(f"[+] Network interface {nEt_interface} MAC address changed to {mAc_addr}\n")

    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to change MAC address\n")
    except Exception as e:
        print(f"[-] An error occurred: {e}\n")

def main():

    #provide description of the script:
    paser = argparse.ArgumentParser(description="Change MAC address of selected network interface")

    #define options for the interface and specified mac address
    paser.add_argument("-i", "--interface", dest="nEt_interface", help="specify the network interface")
    paser.add_argument("-m", "--mac_address", dest="mAc_addr", help="specify new MAC address")
    args = paser.parse_args()
    if not args.nEt_interface:
        paser.error("[-] Error: Interface not specified use --help for usage")
        #sys.exit(1)

    if not args.mAc_addr:
        paser.error("[-] Error: MAC address not specified use --help for usage")
        #sys.exit(1)
    try:
        change_mac(args.nEt_interface, args.mAc_addr)
        script_result = subprocess.check_output(['ifconfig', args.nEt_interface])
        final_script_result = script_result.decode('utf-8')
        print(final_script_result)
    except KeyboardInterrupt:
        print("\n[+] Program interrupted by user.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    if os.getuid() == 0:
        main()
    else:
        print("[-] Please run this program as a superuser (root).")