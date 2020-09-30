#!/usr/bin/env python
# coding=utf-8

# this source code is originally refer from :
# https://gist.githubusercontent.com/pklaus/b5a7876d4d2cf7271873/
# raw/cb089513b185f4128d956eef6e0fb9f5fd583e41/ddnsserver.py

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
import sqlite3
import logging
from configparser import ConfigParser

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. \
        Please install it with `pip` or 'apt install python3-dnslib' in Ubuntu.")
    sys.exit(2)

logging.basicConfig(format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S%z', 
    level=logging.INFO,
    handlers=[
        logging.FileHandler("./log/honeybag-dns.log"),
        logging.StreamHandler()
    ])

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

parser = ConfigParser()
try:
    with open('./conf/honeybag.conf') as config:
        parser.read_file(config)
except IOError:
    logging.error("Missing honeybag.conf file. Please make sure honeybag.conf is located in ./conf folder")
    sys.exit(1)

domain = parser.get('honeybag-config','domain') +"."

D = DomainName(domain)
IP = '127.0.0.1'
TTL = 60 * 5
ts = 0
src_ip = '0'
src_port = 0

records = {
    D: [A(IP)],
    D.ns1: [A(IP)]
}


def dns_response(data):
    request = DNSRecord.parse(data)

    logging.info("-------------- Request --------------")
    logging.info(request)

    # Honeybag simple DNS server with reponse with reply code 3 - No such name
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1,rcode=3), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    # if the incoming DNS request matched with the configured domain name
    if qn == D or qn.endswith('.' + D):
        for name, rrs in records.items():
            print(name, "  ", qn)
            if name.endswith('.' + D):
                # start to look for token values, and other useful alert info
                try:
                    username,systemdomain,systemname,token,domain,ext1,ext = qn.split('.')[-7:]
                    #logging.info("%s.%s.%s.%s.%s.%s.%s", username,systemdomain,systemname,token,domain,ext1,ext)

                except ValueError:
                    logging.info("[Domain matched only] DNS query for domain: %s", qn)
                    logging.info("[Domain matched only] Matched the domain, however no token information")
                    conn1 = sqlite3.connect('./log/honeybag.sqlite')
                    logging.info("[Domain matched only] Database opened successfully");
                    conn1.execute("INSERT INTO hits_domain_matched \
                        (timestamp_hits, source_ip, source_port, domain) \
                        VALUES (?, ?, ?, ?);", (ts, src_ip, src_port, qn))
                    conn1.commit()
                    logging.info("[Domain matched only] Records created successfully");
                    conn1.close()
                    continue

                try:
                    logging.info("[Bingo!] DNS query for domain: %s", qn)
                    logging.info("[Bingo!] Domain matched with token!")
                    conn2 = sqlite3.connect('./log/honeybag.sqlite')
                    logging.info("[Bingo!] Database opened successfully");

                    conn2.execute("INSERT INTO hits_domain_matched \
                        (timestamp_hits, source_ip, source_port, computer_domain, \
                        computer_hostname, computer_username, token_value, domain) \
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?);", \
                        (ts, src_ip, src_port,systemdomain, systemname, username,token,qn))
                    conn2.commit()
                    logging.info("[Bingo!] Records created successfully");
                    conn2.close()

                except Exception:
                    traceback.print_exc(file=sys.stderr)
       
        logging.info("-------------- Reply --------------")
        logging.info("%s", reply)
        return reply.pack()
    else:
        # Log any incoming non-related DNS query, with no any DNS response 
        logging.info("[Incoming] DNS query for domain: %s", qn)
        try:
            conn3 = sqlite3.connect('./log/honeybag.sqlite');

            conn3.execute("INSERT INTO hits_domain_not_matched \
                (timestamp_hits, source_ip, source_port, domain) \
                VALUES (?, ?, ?, ?);", (ts, src_ip, src_port, qn))

            conn3.commit()
            conn3.close()
            logging.info("[Incoming] DNS query logged in database successfully");
        except Exception:
            traceback.print_exc(file=sys.stderr)
        pass


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        global ts 
        ts = time.time()
        global src_ip
        src_ip = self.client_address[0]
        global src_port
        src_port = self.client_address[1]
        logging.info("EPOCH timestamp : " + str(ts))
        logging.info("source ip       : " + str(src_ip))
        logging.info("source port     : " + str(src_port))
        try:
            data = self.get_data()
            logging.info("len(data) %s", len(data))
            if len(data) > 550:
                pass
            else:
                logging.info("data %s", data)
                self.send_data(dns_response(data))
        except Exception:
            pass


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=53, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("  _   _                        _                   ____  _   _ ____  ")
    print(" | | | | ___  _ __   ___ _   _| |__   __ _  __ _  |  _ \| \ | / ___| ")
    print(" | |_| |/ _ \| '_ \ / _ \ | | | '_ \ / _` |/ _` | | | | |  \| \___ \ ")
    print(" |  _  | (_) | | | |  __/ |_| | |_) | (_| | (_| | | |_| | |\  |___) |")
    print(" |_| |_|\___/|_| |_|\___|\__, |_.__/ \__,_|\__, | |____/|_| \_|____/ ")
    print("                         |___/             |___/                     ")
    print("                                                                     ")

    logging.info("Starting Honeybag simple DNS server...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    # TODO: FIX drop privileges

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        logging.info("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
