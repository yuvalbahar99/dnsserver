import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import *


DNS_IP = '10.0.0.138'


def fil(packet):
    return DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0 and packet[DNS].nscount == 0 and \
           packet[DNS].arcount == 0 and packet[DNSQR][0].qtype == 1 and packet.dport == 53
    # and / packet[DNSQR].qname == 'ynet.co.il.'.encode()


def main():
    packets = sniff(count=1, lfilter=fil)
    ip_client = packets[0][IP].src
    my_dns = IP(dst=DNS_IP)/UDP(dport=53, sport=packets[0][UDP].sport)/packets[0][DNS]
    response = sr1(my_dns)
    res_client = IP(dst=ip_client)/UDP(sport=53, dport=packets[0][UDP].sport)/response[DNS]
    send(res_client)


if __name__ == '__main__':
    main()
