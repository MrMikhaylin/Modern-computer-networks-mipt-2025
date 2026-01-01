import json
from enum import Enum
from typing import Dict, Any

class MessageType(Enum):
    REGISTER = "register"          # Клиент регистрируется на сервере
    PEER_INFO = "peer_info"        # Сервер отправляет информацию о peer-е
    HOLE_PUNCH = "hole_punch"      # Сигнал к началу hole punching
    DATA = "data"                  # P2P данные
    KEEP_ALIVE = "keep_alive"      # Поддержание соединения
    ERROR = "error"
    
def create_message(msg_type: MessageType, payload: Dict[str, Any] = None) -> bytes:
    message = {
        "type": msg_type.value,
        "payload": payload or {}
    }
    return json.dumps(message).encode()

def parse_message(data: bytes) -> Dict[str, Any]:
    return json.loads(data.decode())