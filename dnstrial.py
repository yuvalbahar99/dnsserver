import concurrent.futures
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import *
import logging


LIBOT = 2
DNS_IP = '10.0.0.138'
queue_reqs = []
FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
FILENAMELOG = 'dnslog.log'


def fil(packet1):
    return DNS in packet1 and packet1[DNS].opcode == 0 and packet1[DNS].ancount == 0 and packet1[DNS].nscount == 0 and \
           packet1[DNS].arcount == 0 and packet1[DNSQR][0].qtype == 1 and packet1.dport == 53
    # and / packet[DNSQR].qname == 'ynet.co.il.'.encode()


def add_to_queue(packets):
    queue_reqs.append(packets[0])
    logging.debug(str(packets[DNSQR].qname) + ' - into requests queue')


def remove_from_queue():
    packet1 = queue_reqs.pop(0)
    logging.debug(str(packet1[DNSQR].qname) + ' - out of requests queue')
    return packet1


def handle_request(current_packet):
    ip_client = current_packet[IP].src
    my_dns = IP(dst=DNS_IP) / UDP(dport=53, sport=current_packet[UDP].sport) / current_packet[DNS]
    logging.debug(str(current_packet[DNSQR].qname) + ' - waiting for response of the ip')
    response = sr1(my_dns)
    logging.debug(str(current_packet[DNSQR].qname) + ' - received answer(ip address)')
    res_client = IP(dst=ip_client) / UDP(sport=53, dport=current_packet[UDP].sport) / response[DNS]
    send(res_client)
    logging.debug(str(current_packet[DNSQR].qname) + ' - the ip was sent to the client')


def main():
    while True:
        sniff(count=1, lfilter=fil, prn=add_to_queue)
        logging.debug('sniffed packet')
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for pack in queue_reqs:
                future = executor.submit(handle_request, pack)
                futures.append(future)
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                logging.debug(f'Result: {result}')
        """
        handle_request()


if __name__ == '__main__':
    logging.basicConfig(filename=FILENAMELOG, level=logging.DEBUG, format=FORMAT)
    main()
