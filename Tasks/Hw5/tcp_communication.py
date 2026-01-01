import socket
import threading
import time
import ssl
import os
import sys

class TCPServer:
    def __init__(self, host='localhost', port=8888, use_tls=False, certfile=None, keyfile=None):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.certfile = certfile
        self.keyfile = keyfile
        self.socket = None
        self.client_count = 0
        self.clients = {}
        self.running = True
        self.ssl_context = None
        
        if self.use_tls:
            self.setup_ssl_context()
        
    def setup_ssl_context(self):
        """Setup SSL context for server with key logging"""
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

            if self.certfile and self.keyfile and os.path.exists(self.certfile) and os.path.exists(self.keyfile):
                self.ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
                print(f"   Loaded certificate: {self.certfile}, key: {self.keyfile}")
            elif os.path.exists("server.crt") and os.path.exists("server.key"):
                self.ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")
                print("   Loaded default certificates: server.crt, server.key")
            else:
                print("   No certificate files found")
                return
            
            sslkeylogfile = os.getenv('SSLKEYLOGFILE')
            if sslkeylogfile:
                if hasattr(self.ssl_context, 'keylog_filename'):
                    self.ssl_context.keylog_filename = sslkeylogfile
                    print(f"   SSL key logging enabled: {sslkeylogfile}")
                else:
                    print(f"    SSL key logging requires Python 3.8+. Current: {sys.version}")
                    
        except Exception as e:
            print(f"   Error setting up TLS: {e}")
            self.use_tls = False
    
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            
            protocol = "TLS" if self.use_tls else "TCP"
            print(f"   {protocol} Server listening on {self.host}:{self.port}")
            if self.use_tls:
                print("   TLS encryption is ENABLED")
                sslkeylogfile = os.getenv('SSLKEYLOGFILE')
                if sslkeylogfile:
                    print(f"   Key logging to: {sslkeylogfile}")
            print("Server commands:")
            print("  send <client_id> <message>  - Send message to specific client")
            print("  broadcast <message>         - Send message to all clients")
            print("  list                        - Show connected clients")
            print("  quit                        - Exit server")
            print("-" * 50)
            print("Server command: ", end="", flush=True)
            
            accept_thread = threading.Thread(target=self.accept_clients)
            accept_thread.daemon = True
            accept_thread.start()

            self.server_commands()
                
        except Exception as e:
            print(f"   TCP Server error: {e}")
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            for client_id in list(self.clients.keys()):
                self.remove_client(client_id)
            print("   TCP Server stopped")
    
    def accept_clients(self):
        while self.running:
            try:
                client_socket, client_address = self.socket.accept()
                
                if self.use_tls and self.ssl_context:
                    try:
                        client_socket = self.ssl_context.wrap_socket(
                            client_socket, 
                            server_side=True
                        )
                        cipher = client_socket.cipher()
                        print(f"   TLS handshake completed with {client_address}")
                        if cipher:
                            print(f"   Cipher: {cipher[0]}, Version: {cipher[1]}")
                    except ssl.SSLError as e:
                        print(f"   TLS handshake failed with {client_address}: {e}")
                        client_socket.close()
                        continue
                
                self.client_count += 1
                client_id = self.client_count
                
                print(f"\n[New {'TLS ' if self.use_tls else ''}TCP client #{client_id} from {client_address}]")
                print("Server command: ", end="", flush=True)
                
                self.clients[client_id] = {
                    'socket': client_socket,
                    'address': client_address
                }
                
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_id, client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
                welcome_msg = f"Welcome to {'TLS ' if self.use_tls else ''}TCP Server! You are client #{client_id}\n"
                client_socket.send(welcome_msg.encode())
                
            except Exception as e:
                if self.running:
                    print(f"   Error accepting client: {e}")
    
    def handle_client(self, client_id, client_socket, client_address):
        try:
            buffer = b""
            
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    break
                    
                buffer += data
                
                while b'\n' in buffer:
                    message_bytes, buffer = buffer.split(b'\n', 1)
                    
                    try:
                        message = message_bytes.decode('utf-8').strip()
                        if message:
                            print(f"\n[Client {client_id}] {message}")
                            print("Server command: ", end="", flush=True)

                            if message.lower() == 'quit':
                                client_socket.send(b"Goodbye!\n")
                                return
                            elif message.lower() == '/ping':
                                client_socket.send(b"pong\n")
                            elif message.lower() == '/stats':
                                response = f"Server stats: Clients connected: {len(self.clients)}\n"
                                client_socket.send(response.encode())
                            elif message.lower() == '/help':
                                response = "Available commands: /help, /stats, /ping, quit\n"
                                client_socket.send(response.encode())
                            else:
                                response = f"Echo: {message}\n"
                                client_socket.send(response.encode())
                    except UnicodeDecodeError as e:
                        print(f"\n[Client {client_id}] UTF-8 decode error: {e}")
                        print("Server command: ", end="", flush=True)
                        
        except ssl.SSLError as e:
            print(f"\n   TLS error with client {client_id}: {e}")
        except ConnectionResetError:
            print(f"\n[Client {client_id} disconnected unexpectedly]")
            print("Server command: ", end="", flush=True)
        except Exception as e:
            if self.running:
                print(f"\n   Error with client {client_id}: {e}")
                print("Server command: ", end="", flush=True)
        finally:
            self.remove_client(client_id)
    
    def remove_client(self, client_id):
        if client_id in self.clients:
            try:
                self.clients[client_id]['socket'].close()
            except:
                pass
            del self.clients[client_id]
            print(f"\n[Client {client_id} disconnected]")
            print("Server command: ", end="", flush=True)
    
    def server_commands(self):
        while self.running:
            try:
                command = input().strip()
                
                if command.lower() == 'quit':
                    self.running = False
                    print("Shutting down TCP server...")
                    break
                elif command.startswith('send '):
                    parts = command.split(' ', 2)
                    if len(parts) >= 3:
                        try:
                            client_id = int(parts[1])
                            message = parts[2]
                            self.send_to_client(client_id, message)
                        except (ValueError, IndexError):
                            print("Usage: send <client_id> <message>")
                    else:
                        print("Usage: send <client_id> <message>")
                    print("Server command: ", end="", flush=True)
                elif command.startswith('broadcast '):
                    message = command[10:]
                    self.broadcast_to_all(message)
                    print("Server command: ", end="", flush=True)
                elif command == 'list':
                    self.list_clients()
                    print("Server command: ", end="", flush=True)
                else:
                    print("Unknown command. Available: send, broadcast, list, quit")
                    print("Server command: ", end="", flush=True)
                    
            except Exception as e:
                print(f"   Error: {e}")
                print("Server command: ", end="", flush=True)
    
    def send_to_client(self, client_id, message):
        if not self.clients:
            print("No clients connected")
            return
        
        if client_id not in self.clients:
            print(f"Client #{client_id} not found")
            return
            
        try:
            client_socket = self.clients[client_id]['socket']
            full_message = f"Server: {message}\n"
            client_socket.send(full_message.encode())
            print(f"Sent to client #{client_id}: {message}")
        except Exception as e:
            print(f"   Error sending to client #{client_id}: {e}")
            self.remove_client(client_id)
    
    def broadcast_to_all(self, message):
        if not self.clients:
            print("No clients connected")
            return
            
        full_message = f"Broadcast from server: {message}\n"
        disconnected_clients = []
        
        for client_id, client_info in self.clients.items():
            try:
                client_info['socket'].send(full_message.encode())
            except Exception as e:
                disconnected_clients.append(client_id)
        
        for client_id in disconnected_clients:
            self.remove_client(client_id)
            
        print(f"Broadcasted to {len(self.clients)} clients: {message}")
    
    def list_clients(self):
        if not self.clients:
            print("No clients connected")
            return
        
        print("Connected clients:")
        for client_id, client_info in self.clients.items():
            print(f"  {client_id}. {client_info['address']}")

class TCPClient:
    def __init__(self, host='localhost', port=8888, use_tls=False, cafile=None):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.cafile = cafile
        self.running = True
        self.socket = None
        self.ssl_context = None
        
        if self.use_tls:
            self.setup_ssl_context()
        
    def setup_ssl_context(self):
        """Setup SSL context for client with key logging"""
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

            if self.cafile and os.path.exists(self.cafile):
                self.ssl_context.load_verify_locations(cafile=self.cafile)
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                print(f"  Loaded CA certificate: {self.cafile}")
            elif os.path.exists("ca.crt"):
                self.ssl_context.load_verify_locations(cafile="ca.crt")
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                print("   Loaded default CA certificate: ca.crt")
            else:
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
                print("   No CA certificate provided, accepting any certificate")
            
            sslkeylogfile = os.getenv('SSLKEYLOGFILE')
            if sslkeylogfile:
                if hasattr(self.ssl_context, 'keylog_filename'):
                    self.ssl_context.keylog_filename = sslkeylogfile
                    print(f"   SSL key logging enabled: {sslkeylogfile}")
                else:
                    print(f"   SSL key logging requires Python 3.8+. Current: {sys.version}")
                    
        except Exception as e:
            print(f"  Error setting up TLS: {e}")
            self.use_tls = False
    
    def start(self):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            if self.use_tls and self.ssl_context:
                print(f"  Connecting to TLS server at {self.host}:{self.port}...")
                self.socket = self.ssl_context.wrap_socket(
                    raw_socket, 
                    server_hostname=self.host
                )
            else:
                self.socket = raw_socket
                print(f"  Connecting to TCP server at {self.host}:{self.port}...")
            
            self.socket.connect((self.host, self.port))
            
            protocol = "TLS" if self.use_tls else "TCP"
            print(f"  Connected to {protocol} server at {self.host}:{self.port}")
            
            if self.use_tls:
                cipher = self.socket.cipher()
                if cipher:
                    print(f"   TLS connection established:")
                    print(f"   Cipher: {cipher[0]}")
                    print(f"   Protocol: {cipher[1]}")
                    print(f"   Bits: {cipher[2]}")
            
            print("Type 'quit' to exit, '/ping' to test connection")
            print("Client is now listening for server messages...")
            print("Enter message: ", end="", flush=True)
            
            listen_thread = threading.Thread(target=self.listen_messages)
            listen_thread.daemon = True
            listen_thread.start()
            
            self.send_messages()
                
        except ssl.SSLError as e:
            print(f"TLS connection error: {e}")
        except Exception as e:
            print(f"TCP Client error: {e}")
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            print("TCP Client stopped")
    
    def listen_messages(self):
        buffer = b""
        
        while self.running:
            try:
                data = self.socket.recv(1024)
                if not data:
                    print("\nServer closed the connection")
                    self.running = False
                    break
                    
                buffer += data

                while b'\n' in buffer:
                    message_bytes, buffer = buffer.split(b'\n', 1)
                    
                    try:
                        message = message_bytes.decode('utf-8').strip()
                        if message:
                            print(f"\n>>> {message}")
                            print("Enter message: ", end="", flush=True)
                    except UnicodeDecodeError:
                        print(f"\n>>> [Invalid UTF-8 data received]")
                        print("Enter message: ", end="", flush=True)
                    
            except ssl.SSLError as e:
                print(f"\n  TLS error: {e}")
                self.running = False
                break
            except ConnectionResetError:
                print("\nConnection reset by server")
                self.running = False
                break
            except Exception as e:
                if self.running:
                    print(f"\nError receiving message: {e}")
    
    def send_messages(self):
        while self.running:
            try:
                message = input().strip()
                
                if message.lower() == 'quit':
                    self.running = False
                    self.socket.send((message + '\n').encode())
                    break
                elif message.lower() == '/ping':
                    self.socket.send((message + '\n').encode())
                elif message.strip():
                    self.socket.send((message + '\n').encode())
                    print("Enter message: ", end="", flush=True)
                
            except Exception as e:
                print(f"Error sending message: {e}")