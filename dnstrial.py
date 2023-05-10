import concurrent.futures
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from sniffer import Sniffer
from cache import Cache
from datetime import datetime, timedelta

LIBOT = 40
# DNS_IP = '172.16.255.254'
DNS_IP = '10.0.0.138'
queue_reqs = []
FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
FILENAMELOG = 'dnslog.log'
date_format = '%Y-%m-%d %H:%M:%S.%f'


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


def search_domain_in_tables(cache):
    current_packet = remove_from_queue()
    domain = current_packet[DNSQR].qname.decode()
    cache_data = cache.get_domain_info(domain)  # if domain id not exist, get_domain_info returns None
    if cache_data:
        out_of_cache(current_packet, cache_data, domain)
    else:
        logging.debug(domain + 'before handle - not in cache')
        response = handle_request(current_packet)
        if response is not None:
            into_cache(response, cache, domain)


def into_cache(current_packet, cache, domain):
    text_ips = ""
    for answer in current_packet[DNS].an:
        ip_address = str(answer.rdata)
        text_ips += ip_address + ','
    pac_type = current_packet[DNS].an.type
    seconds_to_leave = current_packet[DNS].an.ttl
    now = datetime.now()
    delta = timedelta(seconds=seconds_to_leave)
    ttl = now + delta
    cache.insert_row(text_ips[:-1], domain, str(ttl), str(pac_type))
    logging.debug(domain + ' into the cache')
    cache.print_cache_table()


def out_of_cache(current_packet, cache_data, domain):
    packet_id = current_packet[DNS].id
    logging.debug(domain + 'need to br out of cache')
    logging.debug('after out of cache')
    logging.debug(cache_data)
    if cache_data:
        logging.debug(domain + ' out of the cache')
        ip_text = cache_data[1]
        if "," in ip_text:
            ip_addr_list = ip_text.split(',')
            count = len(ip_addr_list)
        else:
            ip_addr_list = ip_text
            count = 1
        pac_type = int(cache_data[4])
        ttl = datetime.strptime(cache_data[3], date_format)
        now = datetime.now()
        seconds_to_leave = int((ttl - now).total_seconds())
        dns_packet = DNS(qr=1, opcode="QUERY", aa=1, ra=1, ancount=count, id=packet_id,
                         qd=DNSQR(qname=domain, qtype=pac_type),
                         an=DNSRR(rrname=domain, type=pac_type, rdata=ip_addr_list, ttl=seconds_to_leave))
        ip_client = current_packet[IP].src
        logging.debug(dns_packet.show())
        res_client = IP(dst=ip_client) / UDP(sport=53, dport=current_packet[UDP].sport) / dns_packet
        logging.debug('start packet')
        logging.debug(res_client.show())
        logging.debug('end packet')
        send(res_client)


def create_cache():
    cache = Cache()
    cache.create_connection()
    cache.create_tables()
    cache.delete_expired_records()
    cache.print_cache_table()
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
                    executor.submit(search_domain_in_tables(cache))
            except Exception as e:
                logging.debug(f'Error m occurred: {e}')


if __name__ == '__main__':
    logging.basicConfig(filename=FILENAMELOG, level=logging.DEBUG, format=FORMAT)
    main()
