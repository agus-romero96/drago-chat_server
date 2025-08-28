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
                    await connection.send_text(message)

    async def broadcast_to_all(self, message: str, exclude_websocket: Optional[WebSocket] = None):
        for connection in self.user_connections.values():
            if connection is not exclude_websocket:
                await connection.send_text(message)

    def get_users_in_room(self, room_name: str) -> List[str]:
        pass

manager = ConnectionManager()