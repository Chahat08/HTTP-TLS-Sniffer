# CSE 508 HW2: HTTP/TLS packet sniffer using scapy

import argparse
from http import server
from scapy.all import *
import colorama
from datetime import datetime
import cryptography

# getting the colors to put in the terminal output
colorama.init()
GREEN=colorama.Fore.GREEN
RED=colorama.Fore.RED
CYAN=colorama.Fore.CYAN
YELLOW=colorama.Fore.YELLOW
RESET=colorama.Fore.RESET

def packet_callback(packet):
    if packet.haslayer(IP):
        time = datetime.fromtimestamp(float(packet.time))

        src_ip=packet[IP].src
        dst_ip=packet[IP].dst

        src_port=None
        dst_port=None

        if packet.haslayer(TCP): 
            src_port=packet[TCP].sport
            dst_port=packet[TCP].dport

        elif packet.haslayer(UDP):
            src_port=packet[UDP].sport
            dst_port=packet[UDP].dport
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            # checking for http
            if "HTTP" in payload:
                http_info = payload.split('\r\n')
                http_method = http_info[0].split()[0]
                host = ""
                uri = ""
                if http_method == "GET" or http_method == "POST":
                    for line in http_info:
                        if line.startswith("Host:"):
                            host = line.split()[1]
                        elif line.startswith("GET") or line.startswith("POST"):
                            uri = line.split()[1]
                    if host and uri:
                        print(f"{time} {CYAN}HTTP    {RESET} {GREEN}{src_ip}:{src_port}{RESET} -> {RED}{dst_ip}:{dst_port} {RESET} {host} {YELLOW} {http_method} {RESET} {uri}")


        if packet.haslayer(TLSClientHello):
            tls_version = packet[TLSClientHello].version
            
            major_version = (tls_version >> 8) & 0xff
            minor_version = tls_version & 0xff

            major_version=1 # all tls versions 1.0, 1.2 and 1.3 start w 1 so major version can be said to be 1

            # TLS 1.0 is 0x0301 (major version: 3, minor version: 1)
            if minor_version==1:
                minor_version=0
            
            # TLS 1.2 is 0x0303 (major version: 3, minor version: 3)
            elif minor_version==3:
                minor_version=2

            # TLS 1.3 is 0x0304 (major version: 3, minor version: 4)
            else: 
                minor_version=4

            # Convert to human-readable format
            server_name = packet[TLS_Ext_ServerName].servernames[0].servername.decode('utf-8')

            print(f"{time} {CYAN}TLS v{major_version}.{minor_version}{RESET} {GREEN}{src_ip}:{src_port}{RESET} -> {RED}{dst_ip}:{dst_port} {RESET} {server_name}")

if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Packet sniffer for HTTP/TLS traffic.", 
                                     epilog="This packet sniffer is made for CSE 508 HW2, submitted by Chahat Kalsi (115825394).")
    
    #adding the args to the parser
    parser.add_argument("-i", "--interface", type=str, help="Network interface for the capture, eg. eth0, wlan0, etc.")
    parser.add_argument("-r", "--tracefile", type=str, help="Read network trafic from the provided tcpdump-like trace file")
    parser.add_argument("expression", nargs="?", help="berkeley packet filtering expression")

    # get the args provided in the command
    args=parser.parse_args()

    load_layer("tls")
    print(f"{CYAN}------------------------------------------{RESET}")
    print(f"         {YELLOW}HTTP/TLS PACKET SNIFFER{RESET}")
    print(f"{CYAN}------------------------------------------{RESET}")

    if args.interface:
        sniff(iface=args.interface, prn=packet_callback, filter=args.expression)
    elif args.tracefile:
        sniff(offline=args.tracefile, prn=packet_callback, filter=args.expression)
    else:
        sniff(iface=conf.iface, prn=packet_callback, filter=args.expression)





    

