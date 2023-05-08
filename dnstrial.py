import concurrent.futures
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from sniffer import Sniffer
from cache import Cache
from datetime import datetime, timedelta

LIBOT = 40
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


def handle_request(current_packet):
    # while True:
    try:
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
                return response
            else:
                logging.debug(str(current_packet[DNSQR].qname) + ' - no response from the DNS server')
    except Exception as e:
        logging.debug(f'Error h occurred: {e}')
    return None


def search_domain_in_cache(cache):
    current_packet = remove_from_queue()
    domain = current_packet[DNSQR].qname.decode()
    if not cache.check_domain_exists(domain):
        response = handle_request(current_packet)
        if response is not None:
            into_cache(response, cache, domain)
    else:
        out_of_cache(current_packet, cache, domain)


def into_cache(current_packet, cache, domain):
    text_ips = ""
    for answer in current_packet[DNS].an:
        ip_address = answer.rdata
        text_ips += socket.inet_ntoa(ip_address) + ','
    pac_type = current_packet[DNS].an.type.decode
    seconds_to_leave = current_packet[DNS].an.ttl
    now = datetime.now()
    delta = timedelta(seconds=seconds_to_leave)
    ttl = now + delta
    cache.insert_row(text_ips[:-1], domain, ttl, pac_type)


def out_of_cache(current_packet, cache, domain):
    cache_data = cache.get_domain_info(domain)
    ip_text = cache_data[0]
    ip_addr_list = []
    if "," in ip_text:
        ip_list = ip_text.split(',')
        for ip_addr in ip_list:
            ip_addr_list.append(socket.inet_aton(ip_addr))
    else:
        ip_addr_list.append(socket.inet_aton(ip_text))
    ttl = cache_data[2]
    pac_type = cache_data[3]
    now = datetime.now()
    seconds_to_leave = (ttl - now).total_seconds()
    dns_packet = DNS(qr=1, aa=1, ra=1, ancount=1, qd=DNSQR(qname=domain, qtype=pac_type),
                     an=DNSRR(rrname=domain, type=pac_type, rdata=ip_addr_list, ttl=seconds_to_leave))
    ip_client = current_packet[IP].src
    res_client = IP(dst=ip_client) / UDP(sport=53, dport=current_packet[UDP].sport) / dns_packet
    send(res_client)


def create_cache():
    cache = Cache()
    cache.create_connection()
    cache.create_tables()
    cache.delete_all_records()
    return cache


def main():
    cache = create_cache()
    sniffer = Sniffer(queue_reqs)
    sniff_thread = threading.Thread(target=sniffer.sniffing)
    sniff_thread.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=LIBOT) as executor:
        while True:
            try:
                if queue_reqs:
                    executor.submit(search_domain_in_cache(cache))
            except Exception as e:
                logging.debug(f'Error m occurred: {e}')


if __name__ == '__main__':
    logging.basicConfig(filename=FILENAMELOG, level=logging.DEBUG, format=FORMAT)
    main()