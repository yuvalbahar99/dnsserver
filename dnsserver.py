import concurrent.futures
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from sniffer import Sniffer
from cache import Cache
from datetime import datetime, timedelta
from parentalcontrol import ParentalControl
from protocol import Protocol
from users import Users
import threading
import queue
import socket
import ssl

LIBOT = 80
DNS_IP = '172.16.255.254'
# DNS_IP = '10.0.0.138'
FORMAT = '%(asctime)s %(levelname)s %(threadName)s %(message)s'
FILENAMELOG = 'dnslog.log'
date_format = '%Y-%m-%d %H:%M:%S.%f'
PORT = 80
# SERVER_IP = "10.0.0.23"
SERVER_IP = '172.16.15.111'
# SERVER_IP = "172.16.15.49"
queue_reqs = queue.Queue()
COMMAND_LIST = ['S', 'L', 'A', 'R', 'V', 'C']
CRT_FILE = 'certificate.crt'
PRIVATE_KEY_FILE = 'privateKey.key'


def remove_from_queue():
    if not queue_reqs.empty():
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


def create_users_table():
    users_table = Users()
    users_table.create_connection()
    users_table.create_tables()
    # users_table.delete_all_records()
    users_table.print_users_table()
    return users_table


def handle_client(client_socket, parental_control, users_table):
    while True:
        response_data = ''
        flag = False
        try:
            message = client_socket.recv(5).decode()
            if message.startswith('start'):
                while not message.endswith('*'):
                    message += client_socket.recv(1).decode()
            data_len = message[5:-1]  # data len to receive
            data_len = int(data_len)
            if data_len > 0:
                request = client_socket.recv(data_len).decode()
                request_elements = request.split('*')
                command = request_elements[0]
                if command not in COMMAND_LIST:
                    response_data = 'ERROR'
                else:
                    if command == 'S':
                        response_data = sign_up_req(request_elements, users_table)
                    elif command == 'L':
                        response_data = log_in_req(request_elements, users_table)
                    elif command == 'A':
                        response_data = add_blocking_req(request_elements, parental_control)
                    elif command == 'R':
                        response_data = remove_blocking_req(request_elements, parental_control)
                    elif command == 'V':
                        response_data = view_blocking_list_req(parental_control)
                    else:  # command = 'C'
                        flag = True
                        client_socket.close()
                        return
        except:
            response_data = 'ERROR'
        finally:
            if not flag:
                protocol = Protocol(response_data)
                response = protocol.add_protocol()
                client_socket.send(response.encode())


def sign_up_req(request_elements, users_table):
    username = request_elements[1]
    index = 0
    password = ''
    for element in request_elements:
        if index >= 2:
            password += element + '*'
        index += 1
    password = password[:-1]
    username_exist = users_table.username_already_exist(username)
    if not username_exist:
        users_table.add_user(username, password)
        response_data = 'DONE'
    else:
        response_data = 'username is already exist\ntry to sign in with a different username'
    return response_data


def log_in_req(request_elements, users_table):
    username = request_elements[1]
    index = 0
    password = ''
    for element in request_elements:
        if index >= 2:
            password += element + '*'
        index += 1
    password = password[:-1]
    user_is_valid = users_table.user_is_valid(username, password)
    if user_is_valid:
        response_data = 'DONE'
    else:
        response_data = 'wrong username or password\ntry again'
    return response_data


def add_blocking_req(request_elements, parental_control):
    domain = request_elements[1]
    ip = request_elements[2]
    if not domain.endswith('.'):
        domain += '.'
    # להוסיף בדיקה אם זה לא IP אלא כתובת דומיין, לעשות לה sr1

    try:
        parental_control.add_blocking(domain, ip)
        response_data = 'DONE'
    except Exception as err:
        response_data = err
    return response_data


def remove_blocking_req(request_elements, parental_control):
    domain = request_elements[1]
    if not domain.endswith('.'):
        domain += '.'
    response_data = ''
    try:
        response_data = parental_control.remove_blocking(domain)
    except Exception as err:
        response_data = err
    finally:
        return response_data


def view_blocking_list_req(parental_control):
    response_data = ''
    try:
        blocked_list = parental_control.return_block_list()
        for i in blocked_list:
            response_data += i + '\n'
        if response_data != '':
            response_data = response_data[:-1]
    except Exception as err:
        response_data = err
    finally:
        return response_data


def run_server(parental_control, users_table, ssock):
    while True:
        client_socket, client_addr = ssock.accept()
        print("New connection")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, parental_control, users_table))
        client_handler.start()


def main():
    cache = create_cache()
    users_table = create_users_table()
    parental_control = ParentalControl(cache)
    sniffer = Sniffer(queue_reqs)
    sniff_thread = threading.Thread(target=sniffer.sniffing)
    sniff_thread.start()
    print('sniffing')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CRT_FILE, PRIVATE_KEY_FILE)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, PORT))
    server_socket.listen()
    ssock = context.wrap_socket(server_socket, server_side=True)
    print("Server is listening for connections...")
    server_thread = threading.Thread(target=run_server, args=(parental_control, users_table, ssock))
    server_thread.start()
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=LIBOT) as executor:
        while True:
            try:
                if not queue_reqs.empty():
                    executor.submit(search_domain_in_cache, cache)
            except Exception as e:
                logging.debug(f'Error m occurred: {e}')
    """


if __name__ == '__main__':
    logging.basicConfig(filename=FILENAMELOG, level=logging.DEBUG, format=FORMAT)
    main()
