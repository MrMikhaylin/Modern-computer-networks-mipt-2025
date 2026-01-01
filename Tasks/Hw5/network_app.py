import argparse
import os
from tcp_communication import TCPServer, TCPClient

def main():
    parser = argparse.ArgumentParser(description='Network Application - TCP Client/Server with TLS')
    parser.add_argument('--mode', choices=['tcp-server', 'tcp-client', 'udp-server', 'udp-client'],
                       required=True, help='Operation mode')
    parser.add_argument('--host', default='localhost', help='Host address')
    parser.add_argument('--port', type=int, default=8888, help='Port number')
    parser.add_argument('--tls', action='store_true', help='Enable TLS encryption')
    parser.add_argument('--certfile', help='Path to certificate file (for server)')
    parser.add_argument('--keyfile', help='Path to private key file (for server)')
    parser.add_argument('--cafile', help='Path to CA certificate file (for client verification)')
    
    args = parser.parse_args()
    
    port = args.port
    if args.mode.startswith('udp') and args.port == 8888:
        port = 8889

    sslkeylogfile = os.getenv('SSLKEYLOGFILE')
    if sslkeylogfile and args.tls:
        print(f"  SSLKEYLOGFILE is set to: {sslkeylogfile}")
    
    if args.mode == 'tcp-server':
        server = TCPServer(
            args.host, 
            port, 
            use_tls=args.tls,
            certfile=args.certfile,
            keyfile=args.keyfile
        )
        server.start()
    elif args.mode == 'tcp-client':
        client = TCPClient(
            args.host, 
            port, 
            use_tls=args.tls,
            cafile=args.cafile
        )
        client.start()

if __name__ == "__main__":
    main()