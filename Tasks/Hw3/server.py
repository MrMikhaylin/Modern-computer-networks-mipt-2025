import socket
import threading
import logging
from collections import defaultdict
from message_protocol import MessageType, create_message, parse_message

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RendezvousServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.sock = None
        self.clients = {}
        self.pending_peers = defaultdict(list)
        
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        logging.info(f"Rendezvous server started on {self.host}:{self.port}")
        
        try:
            while True:
                data, addr = self.sock.recvfrom(1024)
                threading.Thread(target=self.handle_message, args=(data, addr)).start()
        except KeyboardInterrupt:
            logging.info("Server stopped")
        finally:
            if self.sock:
                self.sock.close()
    
    def handle_message(self, data: bytes, addr: tuple):
        try:
            message = parse_message(data)
            msg_type = message.get("type")
            payload = message.get("payload", {})
            
            client_id = payload.get("client_id")
            room = payload.get("room", "default")
            
            logging.info(f"Received {msg_type} from {addr} (client: {client_id})")
            
            if msg_type == MessageType.REGISTER.value:
                self.handle_register(client_id, addr, room, payload)
            elif msg_type == MessageType.KEEP_ALIVE.value:
                self.handle_keep_alive(client_id, addr)
                
        except Exception as e:
            logging.error(f"Error handling message from {addr}: {e}")
    
    def handle_register(self, client_id: str, addr: tuple, room: str, payload: dict):
        local_addr = payload.get("local_address")

        # Сервер видит реальный внешний адрес через NAT
        external_addr = addr
        
        self.clients[client_id] = {
            "address": addr,
            "local_address": local_addr,
            "external_address": external_addr,
            "room": room
        }
        
        self.pending_peers[room].append(client_id)

        if len(self.pending_peers[room]) >= 2:
            self.pair_peers(room)
    
    def pair_peers(self, room: str):
        if len(self.pending_peers[room]) < 2:
            return
            
        peer1_id, peer2_id = self.pending_peers[room][:2]
        peer1_info = self.clients[peer1_id]
        peer2_info = self.clients[peer2_id]

        self.send_peer_info(peer1_id, peer2_info)
        self.send_peer_info(peer2_id, peer1_info)

        self.pending_peers[room] = self.pending_peers[room][2:]
        
        logging.info(f"Paired {peer1_id} and {peer2_id} in room {room}")
    
    def send_peer_info(self, client_id: str, peer_info: dict):
        if client_id not in self.clients:
            return
            
        client_addr = self.clients[client_id]["address"]
        
        client_net_info = self.clients[client_id]
        connection_type = self.determine_connection_type(client_net_info, peer_info)

        peer_id = None
        for k, v in self.clients.items():
            if v == peer_info:
                peer_id = k
                break
        
        if not peer_id:
            return
        
        message_payload = {
            "peer_id": peer_id,
            "peer_external_address": peer_info["external_address"],  # Реальный внешний адрес
            "peer_local_address": peer_info["local_address"],        # Локальный адрес
            "connection_type": connection_type
        }
        
        message = create_message(MessageType.PEER_INFO, message_payload)
        self.sock.sendto(message, client_addr)
        
        logging.info(f"Sent peer info to {client_id}, connection type: {connection_type}")

    def determine_connection_type(self, client1: dict, client2: dict) -> str:
        client1_ext = client1["external_address"]
        client2_ext = client2["external_address"]
        client1_local = client1["local_address"]
        client2_local = client2["local_address"]
        
        print(f"DEBUG determine_connection_type:")
        print(f"  Client1: ext={client1_ext}, local={client1_local}")
        print(f"  Client2: ext={client2_ext}, local={client2_local}")

        if (client1_local and client2_local and 
            self.is_same_subnet(client1_local[0], client2_local[0])):
            print("  DEBUG: Same subnet - LOCAL")
            return "local"

        client1_behind_nat = client1_ext[0] != client1_local[0]
        client2_behind_nat = client2_ext[0] != client2_local[0]
        
        print(f"  DEBUG: Client1 behind NAT: {client1_behind_nat}")
        print(f"  DEBUG: Client2 behind NAT: {client2_behind_nat}")
        
        if client1_behind_nat and client2_behind_nat:
            if client1_ext[0] == client2_ext[0]:
                print("  DEBUG: Same external IP - ONE NAT")
                return "one_nat"
            else:
                print("  DEBUG: Different external IPs - BOTH NAT")
                return "both_nat"
        elif client1_behind_nat or client2_behind_nat:
            print("  DEBUG: One behind NAT - ONE NAT")
            return "one_nat"
        else:
            print("  DEBUG: Default - BOTH NAT")
            return "both_nat"

    def is_same_subnet(self, ip1: str, ip2: str, mask_bits=24) -> bool:
        try:
            if ip1 == ip2:
                return True
                
            import ipaddress
            net1 = ipaddress.IPv4Network(f"{ip1}/{mask_bits}", strict=False)
            net2 = ipaddress.IPv4Network(f"{ip2}/{mask_bits}", strict=False)
            return net1 == net2
        except:
            return False
    
    def handle_keep_alive(self, client_id: str, addr: tuple):
        if client_id in self.clients:
            self.clients[client_id]["address"] = addr
            self.clients[client_id]["external_address"] = addr

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Rendezvous server for P2P NAT traversal')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    args = parser.parse_args()
    
    server = RendezvousServer(host=args.host, port=args.port)
    server.start()

if __name__ == "__main__":
    main()