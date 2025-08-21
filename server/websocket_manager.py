from typing import List, Dict, DefaultDict
from collections import defaultdict
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        # Maps a room name to a list of active WebSocket connections in that room
        self.rooms: DefaultDict[str, List[WebSocket]] = defaultdict(list)
        # Maps a username to their active WebSocket connection
        self.user_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, username: str, room_name: str):
        await websocket.accept()
        self.rooms[room_name].append(websocket)
        self.user_connections[username] = websocket

    def disconnect(self, websocket: WebSocket, username: str, room_name: str):
        if room_name in self.rooms:
            self.rooms[room_name].remove(websocket)
            # If the room is empty after disconnecting, remove the room key
            if not self.rooms[room_name]:
                del self.rooms[room_name]
        
        if username in self.user_connections:
            del self.user_connections[username]

    async def send_personal_message(self, message: str, username: str):
        if username in self.user_connections:
            websocket = self.user_connections[username]
            await websocket.send_text(message)

    async def broadcast_to_room(self, message: str, room_name: str):
        if room_name in self.rooms:
            for connection in self.rooms[room_name]:
                await connection.send_text(message)

    def get_users_in_room(self, room_name: str) -> List[str]:
        # This is a bit inefficient. A better approach would be to store users per room.
        # For now, this will work. We can optimize later if needed.
        # This requires a reverse lookup from the websocket object back to the username.
        # We will handle this logic in the main endpoint for now.
        # This method is a placeholder for that logic.
        pass

manager = ConnectionManager()