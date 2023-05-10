import logging
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
import socket

HOST_NAME = socket.gethostname()
IP_ADDRESS = socket.getaddrinfo(HOST_NAME, None, socket.AF_INET)[0][4][0]


class Sniffer:
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def fil(self, packet1):
        return DNS in packet1 and IP in packet1 and packet1[IP].src != IP_ADDRESS and packet1[DNS].opcode == 0 \
               and packet1[DNS].qr == 0 and packet1[DNS].ancount == 0 and packet1.dport == 53 and \
               packet1[DNS].nscount == 0 and packet1[DNS].arcount == 0 and packet1[DNSQR][0].qtype == 1
        # and packet1[DNSQR].qname == 'ynet.co.il.'.encode()

    def add_to_queue(self, packet1):
        if packet not in self.queue:
            logging.debug(str(packet1[DNSQR].qname) + ' - before into requests queue')
            self.queue.append(packet1)
            logging.debug(str(packet1[DNSQR].qname) + ' - after into requests queue')

    def sniffing(self):
        logging.debug('sniffing')
        sniff(lfilter=self.fil, prn=self.add_to_queue)

