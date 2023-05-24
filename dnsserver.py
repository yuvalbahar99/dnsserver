import concurrent.futures
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from sniffer import Sniffer
from cache import Cache
from datetime import datetime, timedelta
from parentalcontrol import ParentalControl
import threading
import queue

LIBOT = 40
# DNS_IP = '172.16.255.254'
DNS_IP = '10.0.0.138'
FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
FILENAMELOG = 'dnslog.log'
date_format = '%Y-%m-%d %H:%M:%S.%f'
PORT = 80
SERVER_IP = "10.0.0.23"
# SERVER_IP = "172.16.15.49"
queue_reqs = queue.Queue()


def remove_from_queue():
    if queue_reqs.qsize() != 0:
        packet1 = queue_reqs.get()
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
    cache_data = cache.get_domain_info(domain)  # if domain id not exist, get_domain_info returns None
    if cache_data:  # check for answer in the cache (so the request won't be send out
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
    cache.insert_row(text_ips, domain, ttl, pac_type)
    logging.debug(domain + ' into the cache')
    cache.print_cache_table()


def out_of_cache(current_packet, cache_data, domain):
    packet_id = current_packet[DNS].id
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
        if seconds_to_leave > 9467077826:  # if ttl is longer than 3 year
            seconds_to_leave = 10
        dns_packet = DNS(qr=1, opcode="QUERY", aa=1, ra=1, ancount=count, id=packet_id,
                         qd=DNSQR(qname=domain, qtype=pac_type),
                         an=DNSRR(rrname=domain, type=pac_type, rdata=ip_addr_list, ttl=seconds_to_leave))
        ip_client = current_packet[IP].src
        res_client = IP(dst=ip_client) / UDP(sport=53, dport=current_packet[UDP].sport) / dns_packet
        # logging.debug(res_client.show())
        send(res_client)


def create_cache():
    cache = Cache()
    cache.create_connection()
    cache.create_tables()
    cache.delete_expired_records()
    cache.print_cache_table()
    return cache


def handle_client(client_socket, parental_control):
    request = client_socket.recv(7).decode()
    if request.startswith('*start*'):
        while not request.endswith('*end*'):
            request += client_socket.recv(1).decode()
    command = request[7]
    address = request[8:-5]
    try:
        if command == 'A':
            parental_control.add_blocking(address)
            response = "*start*DONE*end*"
        elif command == 'R':
            parental_control.remove_blocking(address)
            response = "*start*DONE*end*"
        else:
            text_list = ''
            blocked_list = parental_control.return_block_list()
            for i in blocked_list:
                text_list += i + '\n'
            text_list = text_list[:-1]
            response = "*start*" + text_list + "*end*"
    except Exception as e:
        response = "*start*ERROR*end*"
    client_socket.send(response.encode())


def run_server(server_socket, parental_control):
    while True:
        client_socket, client_address = server_socket.accept()
        print("New connection")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, parental_control))
        client_handler.start()


def main():
    cache = create_cache()
    parental_control = ParentalControl(cache)
    sniffer = Sniffer(queue_reqs)
    sniff_thread = threading.Thread(target=sniffer.sniffing)
    sniff_thread.start()
    print('sniffing')
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, PORT))
    server_socket.listen()
    print("Server is listening for connections...")
    server_thread = threading.Thread(target=run_server, args=(server_socket, parental_control))
    server_thread.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=LIBOT) as executor:
        while True:
            try:
                if queue_reqs.qsize() != 0:
                    executor.submit(search_domain_in_cache, cache)
            except Exception as e:
                logging.debug(f'Error m occurred: {e}')


if __name__ == '__main__':
    logging.basicConfig(filename=FILENAMELOG, level=logging.DEBUG, format=FORMAT)
    main()
