import socket
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import *
import logging


DNS_IP = '172.16.255.254'
queue_reqs = []


def fil(packet):
    return DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0 and packet[DNS].nscount == 0 and \
           packet[DNS].arcount == 0 and packet[DNSQR][0].qtype == 1 and packet.dport == 53
    # and / packet[DNSQR].qname == 'ynet.co.il.'.encode()


def add_to_queue(packets):
    queue_reqs.append(packets[0])
    logging.debug(str(packets[DNSQR].qname) + ' - into requests queue')


def remove_from_queue():
    packet = queue_reqs.pop(0)
    logging.debug(str(packet[DNSQR].qname) + ' - out of requests queue')
    return packet


def main():
    while True:
        sniff(count=1, lfilter=fil, prn=add_to_queue)
        logging.debug('sniffed packet')
        current_packet = remove_from_queue()
        ip_client = current_packet[IP].src
        my_dns = IP(dst=DNS_IP)/UDP(dport=53, sport=current_packet[UDP].sport)/current_packet[DNS]
        logging.debug(str(current_packet[DNSQR].qname) + ' - waiting for response of the ip')
        response = sr1(my_dns)
        logging.debug(str(current_packet[DNSQR].qname) + ' - received answer(ip address)')
        res_client = IP(dst=ip_client)/UDP(sport=53, dport=current_packet[UDP].sport)/response[DNS]
        send(res_client)
        logging.debug(str(current_packet[DNSQR].qname) + ' - the ip was sent to the client')


if __name__ == '__main__':
    logging.basicConfig(filename="dnslog.log", level=logging.DEBUG)
    main()
