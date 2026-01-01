#!/usr/bin/env python3

import socket
import threading
import time

class UDPServer:
    def __init__(self, host='localhost', port=8889):
        self.host = host
        self.port = port
        self.socket = None
        self.client_count = 0
        self.clients = {}  # {client_address: {"id": int, "last_seen": float}}
        self.running = True
        
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))

            print(f"UDP Server listening on {self.host}:{self.port}")
            print("UDP Server is connectionless - accepts messages from any client")
            print("Server commands:")
            print("  send <client_id> <message>  - Send message to specific client")
            print("  broadcast <message>         - Send message to all clients")
            print("  list                        - Show connected clients")
            print("  quit                        - Exit server")
            print("-" * 50)
            print("Server command: ", end="", flush=True)
             
            # Start thread for accepting clients
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            self.send_messages()
                    
        except Exception as e:
            print(f"UDP Server error: {e}")
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            print("UDP Server stopped")
    
    def receive_messages(self):
        while self.running:
            try:
                data, client_address = self.socket.recvfrom(1024)
                
                is_new_client = False
                if client_address not in self.clients:
                    self.client_count += 1
                    self.clients[client_address] = {
                        "id": self.client_count,
                        "last_seen": time.time()
                    }
                    is_new_client = True
                    print(f"\n[New UDP client #{self.client_count} from {client_address}]")
                    print("Server command: ", end="", flush=True)
                else:
                    self.clients[client_address]["last_seen"] = time.time()
                
                message = data.decode().strip()
                print(f"\n[Client {self.clients[client_address]['id']}] {message}")
                
                response = self.process_message(message, client_address, is_new_client)
                if response:
                    self.socket.sendto(response.encode(), client_address)
                        
                self.cleanup_clients()
                print("Server command: ", end="", flush=True)
                    
            except Exception as e:
                if self.running:
                    print(f"\nError processing UDP message: {e}")
    
    def send_messages(self):
        while self.running:
            try:
                command = input().strip()
                
                if command.lower() == 'quit':
                    print("Shutting down UDP server...")
                    self.running = False
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
                print(f"Error: {e}")
                print("Server command: ", end="", flush=True)
    
    def get_client_by_id(self, client_id):
        for address, info in self.clients.items():
            if info["id"] == client_id:
                return address
        return None
    
    def send_to_client(self, client_id, message):
        if not self.clients:
            print("No clients connected")
            return
        
        client_address = self.get_client_by_id(client_id)
        if not client_address:
            print(f"Client #{client_id} not found")
            return
            
        full_message = f"Server: {message}"
        self.socket.sendto(full_message.encode(), client_address)
        print(f"Sent to client #{client_id}: {message}")
        self.clients[client_address]["last_seen"] = time.time()
    
    def broadcast_to_all(self, message):
        if not self.clients:
            print("No clients connected")
            return
            
        full_message = f"Broadcast from server: {message}"
        current_time = time.time()
        for client_address in self.clients.keys():
            self.socket.sendto(full_message.encode(), client_address)
            self.clients[client_address]["last_seen"] = current_time
        print(f"Broadcasted to {len(self.clients)} clients: {message}")
    
    def list_clients(self):
        if not self.clients:
            print("No clients connected")
            return
        
        print("Connected clients:")
        for address, info in self.clients.items():
            client_id = info["id"]
            last_seen = time.time() - info["last_seen"]
            print(f"  Client #{client_id}: {address} (last seen {last_seen:.1f}s ago)")

    def process_message(self, message, client_address, is_new_client):
        client_id = self.clients[client_address]["id"]
        
        if is_new_client:
            return f"Welcome to UDP Server! You are client #{client_id}"
        
        if message.lower() == 'quit':
            print(f"Client #{client_id} disconnected")
            del self.clients[client_address]
            return "Goodbye from UDP Server!"
        elif message.lower() == '/stats':
            active_clients = len(self.clients)
            return f"UDP Server stats: Total clients: {self.client_count}, Active: {active_clients}"
        elif message.lower() == '/ping':
            return "pong"
        elif message.lower() == '/help':
            return "Available commands: /ping, /stats, quit, /help"
        else:
            return f"UDP Echo (client #{client_id}): {message}"
    
    def cleanup_clients(self):
        current_time = time.time()
        expired_clients = [
            addr for addr, info in self.clients.items() 
            if current_time - info["last_seen"] > 300
        ]
        for addr in expired_clients:
            client_id = self.clients[addr]["id"]
            print(f"Client #{client_id} timed out")
            del self.clients[addr]

class UDPClient:
    def __init__(self, host='localhost', port=8889):
        self.host = host
        self.port = port
        self.server_address = (host, port)
        self.running = True
        self.socket = None
        self.client_id = None
        
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(1.0)
            print(f"UDP Client ready to send to {self.host}:{self.port}")
            print("Note: UDP is connectionless - messages may be lost!")
            print("Type 'quit' to exit")
            print("Connecting to server...")

            self.socket.sendto(b"/ping", self.server_address)
            
            listen_thread = threading.Thread(target=self.listen_messages)
            listen_thread.daemon = True
            listen_thread.start()
            
            self.send_messages()
                
        except Exception as e:
            print(f"UDP Client error: {e}")
        finally:
            self.running = False
            if self.socket:
                self.socket.close()
            print("UDP Client stopped")
    
    def listen_messages(self):
        while self.running:
            try:
                data, server_addr = self.socket.recvfrom(1024)
                message = data.decode()
                
                if "You are client #" in message and self.client_id is None:
                    try:
                        self.client_id = int(message.split("#")[1].split()[0])
                        print(f"\n>>> {message}")
                        print(f"Successfully registered as client #{self.client_id}")
                        print("Client is now listening for server messages...")
                    except:
                        print(f"\n>>> {message}")
                else:
                    print(f"\n>>> {message}")
                
                print("Enter message: ", end="", flush=True)
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"\nError receiving message: {e}")
    
    def send_messages(self):
        while self.running:
            try:
                message = input().strip()
                
                if message.lower() == 'quit':
                    self.running = False
                    self.socket.sendto(message.encode(), self.server_address)
                    break
                elif message.strip():
                    self.socket.sendto(message.encode(), self.server_address)
                    print("Enter message: ", end="", flush=True)
                
            except Exception as e:
                print(f"Error sending message: {e}")