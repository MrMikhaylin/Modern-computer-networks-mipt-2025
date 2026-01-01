#!/usr/bin/env python3

import argparse
from tcp_communication import TCPServer, TCPClient
from udp_communication import UDPServer, UDPClient

def main():
    parser = argparse.ArgumentParser(description='Network Application - TCP/UDP Client/Server')
    parser.add_argument('--mode', choices=['tcp-server', 'tcp-client', 'udp-server', 'udp-client'],
                       required=True, help='Operation mode')
    parser.add_argument('--host', default='localhost', help='Host address')
    parser.add_argument('--port', type=int, default=8888, help='Port number')
    
    args = parser.parse_args()
    
    port = args.port
    # меняем порт для udp соединения, чтобы не было конфликтов с tcp соединением
    if args.mode.startswith('udp') and args.port == 8888:
        port = 8889
    
    if args.mode == 'tcp-server':
        server = TCPServer(args.host, port)
        server.start()
    elif args.mode == 'tcp-client':
        client = TCPClient(args.host, port)
        client.start()
    elif args.mode == 'udp-server':
        server = UDPServer(args.host, port)
        server.start()
    elif args.mode == 'udp-client':
        client = UDPClient(args.host, port)
        client.start()

if __name__ == "__main__":
    main()