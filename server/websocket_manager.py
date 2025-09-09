from typing import List, Dict, DefaultDict, Optional
from collections import defaultdict
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.rooms: DefaultDict[str, List[WebSocket]] = defaultdict(list)
        self.user_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, username: str, room_name: str):
        await websocket.accept()
        self.rooms[room_name].append(websocket)
        self.user_connections[username] = websocket

    def disconnect(self, websocket: WebSocket, username: str, room_name: str):
        if room_name in self.rooms and websocket in self.rooms[room_name]:
            self.rooms[room_name].remove(websocket)
            if not self.rooms[room_name]:
                del self.rooms[room_name]
        
        if username in self.user_connections:
            del self.user_connections[username]

    async def send_personal_message(self, message: str, username: str):
        if username in self.user_connections:
            websocket = self.user_connections[username]
            await websocket.send_text(message)

    async def broadcast_to_room(self, message: str, room_name: str, exclude_websocket: Optional[WebSocket] = None):
        if room_name in self.rooms:
            for connection in self.rooms[room_name]:
                if connection is not exclude_websocket:
                    try:
                        await connection.send_text(message)
                    except Exception as e:
                        print(f"!!! ERROR al enviar texto a una conexión: {e}. Continuando.")

    async def broadcast_binary_to_room(self, data: bytes, room_name: str, exclude_websocket: Optional[WebSocket] = None):
        """Envía datos binarios a todos en una sala, excluyendo al remitente."""
        if room_name in self.rooms:
            for connection in self.rooms[room_name]:
                if connection is not exclude_websocket:
                    try:
                        await connection.send_bytes(data)
                    except Exception as e:
                        print(f"!!! ERROR al enviar binarios a una conexión: {e}. Continuando.")

    # --- FUNCIÓN CORREGIDA / AÑADIDA DE NUEVO ---
    async def broadcast_to_all(self, message: str, exclude_websocket: Optional[WebSocket] = None):
        """Envía un mensaje de texto a todos los usuarios conectados."""
        for connection in self.user_connections.values():
            if connection is not exclude_websocket:
                try:
                    await connection.send_text(message)
                except Exception as e:
                    print(f"!!! ERROR al enviar a todos: {e}. Continuando.")
    # --- FIN DE LA CORRECCIÓN ---

    def get_users_in_room(self, room_name: str) -> List[str]:
        pass

manager = ConnectionManager()