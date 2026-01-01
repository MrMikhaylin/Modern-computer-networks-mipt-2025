import socket
import threading
import time
import uuid
import logging
import argparse
from message_protocol import MessageType, create_message, parse_message

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class P2PClient:
    def __init__(self, rendezvous_host='localhost', rendezvous_port=5000, 
                 local_port=0, scenario=None, name=None):
        if name:
            self.client_id = name
        else:
            self.client_id = str(uuid.uuid4())[:8]
            
        self.rendezvous_addr = (rendezvous_host, rendezvous_port)
        self.forced_scenario = scenario

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', local_port))
        self.sock.settimeout(5.0)

        base_local_addr = self.sock.getsockname()
        real_ip = self.get_real_local_ip()
        self.local_address = (real_ip, base_local_addr[1]) if real_ip else base_local_addr

        self.external_address = None
        
        self.peer_info = None
        self.is_connected = False
        self.connection_type = None
        self.peer_addr = None
        self.chat_started = False
        
        logging.info(f"Client {self.client_id} started on {self.local_address}")

    def get_real_local_ip(self):
        try:
            import subprocess
            result = subprocess.run(['ip', 'route', 'get', '1'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'src' in line:
                        parts = line.split()
                        src_index = parts.index('src') + 1
                        if src_index < len(parts):
                            ip = parts[src_index]
                            if ip and ip != '0.0.0.0':
                                return ip
        except Exception as e:
            print(f"Error with ip route: {e}")
        
        try:
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_sock.connect((self.rendezvous_addr[0], self.rendezvous_addr[1]))
            local_ip = temp_sock.getsockname()[0]
            temp_sock.close()
            if local_ip and local_ip != '0.0.0.0':
                return local_ip
        except:
            pass
        
        return None
        
    def discover_network_info(self):
        if self.forced_scenario == "local":
            self.external_address = self.local_address
            self.connection_type = "local"
            logging.info(f"LOCAL scenario: {self.local_address}")
            
        elif self.forced_scenario == "one_nat":
            self.external_address = self.local_address
            self.connection_type = "one_nat"
            logging.info(f"ONE-NAT scenario: {self.local_address}")
                
        elif self.forced_scenario == "both_nat":
            self.external_address = self.local_address
            self.connection_type = "both_nat"
            logging.info(f"BOTH-NAT scenario: {self.local_address}")
        else:
            self.external_address = self.local_address
            logging.info(f"Auto scenario: {self.local_address}")
            
        return self.local_address, self.external_address
    
    def register_with_server(self, room="default"):
        local_addr, external_addr = self.discover_network_info()

        payload = {
            "client_id": self.client_id,
            "room": room,
            "local_address": list(local_addr),
            "external_address": list(local_addr),
            "scenario": self.forced_scenario
        }
        
        message = create_message(MessageType.REGISTER, payload)
        self.sock.sendto(message, self.rendezvous_addr)
        
        logging.info(f"Client {self.client_id} registered with server")
    
    def start_receiver(self):
        def receiver():
            while True:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    self.handle_incoming_message(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.is_connected:
                        logging.error(f"Error receiving message: {e}")
        
        thread = threading.Thread(target=receiver, daemon=True)
        thread.start()
    
    def handle_incoming_message(self, data: bytes, addr: tuple):
        try:
            message = parse_message(data)
            msg_type = message.get("type")
            payload = message.get("payload", {})
            
            if msg_type == MessageType.PEER_INFO.value:
                self.handle_peer_info(payload, addr)
            elif msg_type == MessageType.DATA.value:
                self.handle_peer_data(payload, addr)
                
        except Exception as e:
            logging.error(f"Error handling message from {addr}: {e}")
    
    def handle_peer_info(self, payload: dict, addr: tuple):
        self.peer_info = {
            "peer_id": payload["peer_id"],
            "external_address": tuple(payload["peer_external_address"]),  # Реальный внешний адрес
            "local_address": tuple(payload["peer_local_address"])         # Локальный адрес
        }
        self.connection_type = payload.get("connection_type", "unknown")
        
        logging.info(f"Received peer info: {self.peer_info}")
        logging.info(f"Connection type: {self.connection_type}")

        self.start_hole_punching()
    
    def start_hole_punching(self):
        """Начало процесса hole punching"""
        logging.info("Starting hole punching...")
        
        if not self.peer_info:
            logging.error("No peer info available")
            return

        addresses_to_try = []
        
        if self.connection_type == "local":
            addresses_to_try.append(self.peer_info["local_address"])
            logging.info("Trying local address (same network)")
        else:
            addresses_to_try.append(self.peer_info["external_address"])
            logging.info("Trying external address (NAT traversal)")
        
        logging.info(f"Will try addresses: {addresses_to_try}")

        for i in range(5):
            for addr in addresses_to_try:
                self.send_hole_punch_attempt(addr)
            time.sleep(1)
    
    def send_hole_punch_attempt(self, addr: tuple):
        payload = {
            "client_id": self.client_id,
            "message": "HOLE_PUNCH_ATTEMPT",
            "timestamp": time.time()
        }
        message = create_message(MessageType.DATA, payload)
        
        try:
            self.sock.sendto(message, addr)
            logging.info(f"Sent hole punch attempt to {addr}")
        except Exception as e:
            logging.error(f"Failed to send to {addr}: {e}")
    
    def handle_peer_data(self, payload: dict, addr: tuple):
        peer_id = payload.get("client_id")
        message_text = payload.get("message", "")

        if peer_id == self.client_id:
            return
            
        logging.info(f"Received from {peer_id} ({addr}): {message_text}")
        
        if "HOLE_PUNCH_ATTEMPT" in message_text:
            if not self.is_connected:
                response_payload = {
                    "client_id": self.client_id,
                    "message": "HOLE_PUNCH_RESPONSE",
                    "timestamp": time.time()
                }
                response_message = create_message(MessageType.DATA, response_payload)
                self.sock.sendto(response_message, addr)
                logging.info(f"Connection established with {peer_id} at {addr}!")
                self.is_connected = True
                self.peer_addr = addr

                if not self.chat_started:
                    self.chat_started = True
                    self.start_chat(peer_id, addr)
            else:
                response_payload = {
                    "client_id": self.client_id,
                    "message": "ALREADY_CONNECTED",
                    "timestamp": time.time()
                }
                response_message = create_message(MessageType.DATA, response_payload)
                self.sock.sendto(response_message, addr)
                
        elif "HOLE_PUNCH_RESPONSE" in message_text and not self.is_connected:
            logging.info(f"Connection confirmed with {peer_id} at {addr}!")
            self.is_connected = True
            self.peer_addr = addr
            
            if not self.chat_started:
                self.chat_started = True
                self.start_chat(peer_id, addr)
        
        elif self.is_connected :
            if "Hello from" in message_text or "ALREADY_CONNECTED" in message_text:
                logging.info(f"Chat message from {peer_id}: {message_text}")
            else:
                logging.info(f"Message from {peer_id}: {message_text}")
    
    def start_chat(self, peer_id: str, peer_addr: tuple):
        def chat_sender():
            time.sleep(1)
            
            message_count = 0
            max_messages = 5
            
            while self.is_connected and message_count < max_messages:
                try:
                    message_count += 1
                    payload = {
                        "client_id": self.client_id,
                        "message": f"Hello from {self.client_id}! Message #{message_count}",
                        "timestamp": time.time()
                    }
                    message = create_message(MessageType.DATA, payload)
                    self.sock.sendto(message, peer_addr)
                    logging.info(f"Sent message #{message_count} to {peer_id}")
                    time.sleep(2)
                    
                    if message_count >= max_messages:
                        logging.info(f"Test completed! Sent {max_messages} messages.")
                        break
                        
                except Exception as e:
                    logging.error(f"Error sending message: {e}")
                    break
        
        thread = threading.Thread(target=chat_sender, daemon=True)
        thread.start()
    
    def send_message(self, text: str):
        if self.is_connected and self.peer_addr:
            payload = {
                "client_id": self.client_id,
                "message": text,
                "timestamp": time.time()
            }
            
            message = create_message(MessageType.DATA, payload)
            self.sock.sendto(message, self.peer_addr)
            logging.info(f"Sent: {text}")
            return True
        else:
            logging.error("Not connected to peer")
            return False
    
    def wait_for_connection(self, timeout=30):
        logging.info(f"Waiting for connection (timeout: {timeout}s)...")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.is_connected:
                logging.info("P2P connection established!")
                return True
            time.sleep(0.1)
        
        logging.error("Failed to establish P2P connection within timeout")
        return False

    def close(self):
        self.is_connected = False
        if self.sock:
            self.sock.close()

def parse_arguments():
    parser = argparse.ArgumentParser(description='P2P Client with NAT traversal')
    parser.add_argument('--port', type=int, default=0, help='Local port to bind (0=random)')
    parser.add_argument('--server-port', type=int, default=5000, help='Rendezvous server port')
    parser.add_argument('--server-host', default='localhost', help='Rendezvous server host')
    parser.add_argument('--scenario', choices=['local', 'one_nat', 'both_nat'], 
                       help='Force scenario type for testing')
    parser.add_argument('--name', help='Client name for identification')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    client = P2PClient(
        rendezvous_host=args.server_host,
        rendezvous_port=args.server_port,
        local_port=args.port,
        scenario=args.scenario,
        name=args.name
    )
    
    try:
        client.start_receiver()
        client.register_with_server()

        if client.wait_for_connection(timeout=30):
            logging.info("Connection is active! You can now send messages.")
            logging.info("Type messages and press Enter (or 'quit' to exit):")
            
            while client.is_connected:
                try:
                    user_input = input("> ").strip()
                    if user_input.lower() == 'quit':
                        logging.info("Exiting...")
                        break
                    if user_input:
                        client.send_message(user_input)
                except KeyboardInterrupt:
                    logging.info("\nExiting...")
                    break
                except EOFError:
                    break
        else:
            logging.error("Failed to establish P2P connection")
            
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    main()