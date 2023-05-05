import concurrent.futures
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from sniffer import Sniffer

LIBOT = 4
DNS_IP = '172.16.255.254'
queue_reqs = []
FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
FILENAMELOG = 'dnslog.log'


def remove_from_queue():
    if queue_reqs:
        packet1 = queue_reqs.pop(0)
        logging.debug(str(packet1[DNSQR].qname) + ' - out of requests queue')
        return packet1
    return None


def handle_request():
    while True:
        try:
            current_packet = remove_from_queue()
            if current_packet is not None:
                ip_client = current_packet[IP].src
                my_dns = IP(dst=DNS_IP) / UDP(dport=53, sport=current_packet[UDP].sport) / current_packet[DNS]
                logging.debug(str(current_packet[DNSQR].qname) + ' - waiting for response of the ip')
                response = sr1(my_dns, timeout=1)
                if response:
                    logging.debug(str(current_packet[DNSQR].qname) + ' - received answer(ip address)')
                    res_client = IP(dst=ip_client) / UDP(sport=53, dport=current_packet[UDP].sport) / response[DNS]
                    send(res_client)
                    logging.debug(str(current_packet[DNSQR].qname) + ' - the ip was sent to the client')
                else:
                    logging.debug(str(current_packet[DNSQR].qname) + ' - no response from the DNS server')
        except Exception as e:
            logging.debug(f'Error h occurred: {e}')


def main():
    sniffer = Sniffer(queue_reqs)
    sniff_thread = threading.Thread(target=sniffer.sniffing)
    sniff_thread.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=LIBOT-1) as executor:
        while True:
            try:
                if queue_reqs:
                    executor.submit(handle_request)
            except Exception as e:
                logging.debug(f'Error m occurred: {e}')


if __name__ == '__main__':
    logging.basicConfig(filename=FILENAMELOG, level=logging.DEBUG, format=FORMAT)
    main()
