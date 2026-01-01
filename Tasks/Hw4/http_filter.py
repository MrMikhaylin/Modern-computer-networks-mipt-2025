from netfilterqueue import NetfilterQueue
from scapy.all import *
import re

class HTTPFilter:
    def __init__(self, rules_file='rules.conf'):
        self.rules = self.load_rules(rules_file)
        print("DEBUG: Filter initialized")
        
    def load_rules(self, rules_file):
        rules = []
        try:
            with open(rules_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            rule_part = line.split(':', 1)[1].strip()
                            rule_dict = {}
                            for item in rule_part.split():
                                if '=' in item:
                                    key, value = item.split('=', 1)
                                    if key == 'action':
                                        rule_dict[key] = value
                                    else:
                                        if 'filters' not in rule_dict:
                                            rule_dict['filters'] = {}
                                        rule_dict['filters'][key] = value
                            rules.append(rule_dict)
            print(f"DEBUG: Loaded {len(rules)} rules with AND logic")
        except Exception as e:
            print(f"ERROR loading rules: {e}")
        return rules

    def parse_http(self, payload):
        try:
            http_data = {}
            data_str = payload.decode('utf-8', errors='ignore')
            
            lines = data_str.split('\r\n')
            if lines:
                first_line = lines[0]
                parts = first_line.split()
                if len(parts) >= 2:
                    http_data['method'] = parts[0]
                    http_data['url'] = parts[1]
            
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    http_data[key.strip().lower()] = value.strip()
            
            return http_data
        except Exception as e:
            return {}

    def check_rules(self, http_data):
        print(f"DEBUG: Checking rules for {http_data}")
        for i, rule in enumerate(self.rules):
            match = True
            print(f"DEBUG: Testing rule {i}: {rule}")
            
            # Проверяем ВСЕ фильтры в правиле (логика И)
            if 'filters' in rule:
                for field, pattern in rule['filters'].items():
                    if field in http_data:
                        if not re.search(pattern, http_data[field], re.IGNORECASE):
                            print(f"DEBUG: Rule {i} failed - field '{field}' value '{http_data[field]}' doesn't match pattern '{pattern}'")
                            match = False
                            break
                        else:
                            print(f"DEBUG: Rule {i} field '{field}' matched: '{http_data[field]}' == '{pattern}'")
                    else:
                        print(f"DEBUG: Rule {i} failed - field '{field}' not in HTTP data")
                        match = False
                        break
            
            if match:
                action = rule.get('action', 'accept')
                print(f"DEBUG: Rule {i} MATCHED - Action: {action}")
                return action
        
        print("DEBUG: No rules matched, default ACCEPT")
        return 'accept'

    def process_packet(self, packet):
        try:
            pkt = IP(packet.get_payload())
            
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80 or 
                                      pkt[TCP].dport == 8000 or pkt[TCP].sport == 8000):
                payload = bytes(pkt[TCP].payload)
                
                if payload and len(payload) > 0:
                    if b'HTTP' in payload or b'GET' in payload or b'POST' in payload:
                        http_data = self.parse_http(payload)
                        
                        if http_data:
                            action = self.check_rules(http_data)
                            
                            if action == 'drop':
                                print(f"BLOCKED: {http_data.get('method', '')} {http_data.get('url', '')} User-Agent: {http_data.get('user-agent', '')}")
                                packet.drop()
                                return
            
            packet.accept()
        except Exception as e:
            print(f"ERROR processing packet: {e}")
            packet.accept()

def main():
    nfqueue = NetfilterQueue()
    http_filter = HTTPFilter()
    
    nfqueue.bind(5, http_filter.process_packet)
    
    try:
        print("HTTP filter started on queue 5")
        nfqueue.run()
    except KeyboardInterrupt:
        print("Filter stopped.")
    finally:
        nfqueue.unbind()

if __name__ == '__main__':
    main()