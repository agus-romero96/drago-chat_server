import json
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Query
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from .database import create_db_and_tables, get_db
from .models import User, UserRole, Room
from .auth import (
    get_password_hash, verify_password, create_access_token, 
    get_current_active_user, require_role, get_current_user
)
from .websocket_manager import manager
from . import schemas

app = FastAPI(title="DragoChat Server")

@app.on_event("startup")
async def on_startup():
    await create_db_and_tables()

#
# Authentication Endpoints
#
@app.post("/register", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
async def register_user(form_data: schemas.UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == form_data.username))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")

    hashed_password = get_password_hash(form_data.password)
    
    # Make the first registered user an ADMIN
    result = await db.execute(select(User))
    is_first_user = result.first() is None
    user_role = UserRole.ADMIN if is_first_user else UserRole.COMMON_USER

    new_user = User(username=form_data.username, hashed_password=hashed_password, role=user_role)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == form_data.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(form_data.password, user.hashed_password) or user.is_banned:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password, or user is banned",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

#
# User Endpoints
#
@app.get("/users/me", response_model=schemas.UserOut)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.put("/users/me/status", response_model=schemas.UserOut)
async def update_status_message(
    status_update: schemas.StatusUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    current_user.status_message = status_update.status_message
    await db.commit()
    await db.refresh(current_user)
    return current_user

#
# Room Endpoints
#
@app.post("/rooms", response_model=schemas.RoomOut, status_code=status.HTTP_201_CREATED)
async def create_room(
    room_data: schemas.RoomCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Room).filter(Room.name == room_data.name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Room name already exists")

    new_room = Room(**room_data.dict(), owner_id=current_user.id)
    db.add(new_room)
    await db.flush() # Flush para obtener el ID de la nueva sala antes del commit.

    # Ahora new_room.id está disponible.
    current_user.current_room_id = new_room.id
    
    await db.commit() # El commit guarda todos los cambios pendientes.
    
    # Refrescamos ambos objetos para asegurarnos de que tienen el estado final de la DB.
    await db.refresh(new_room)
    await db.refresh(current_user)

    return new_room

@app.get("/rooms", response_model=List[schemas.RoomOut])
async def list_public_rooms(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Room).filter(Room.is_private == False).options(selectinload(Room.owner)))
    rooms = result.scalars().all()
    return rooms

@app.post("/rooms/{room_name}/join", response_model=schemas.UserOut)
async def join_room(
    room_name: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Room).filter(Room.name == room_name))
    room = result.scalar_one_or_none()
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")
    if room.is_private and room.owner_id != current_user.id:
         # Basic private check, can be expanded with an invitation system
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This room is private")

    current_user.current_room_id = room.id
    await db.commit()
    await db.refresh(current_user)
    return current_user

@app.post("/rooms/leave", response_model=schemas.UserOut)
async def leave_room(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    current_user.current_room_id = None
    await db.commit()
    await db.refresh(current_user)
    return current_user

@app.put("/rooms/{room_name}/privacy", status_code=status.HTTP_204_NO_CONTENT)
async def set_room_privacy(
    room_name: str,
    privacy_data: schemas.RoomPrivacyUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Room).filter(Room.name == room_name))
    room = result.scalar_one_or_none()
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")
    if room.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the room owner can change privacy")
    
    room.is_private = privacy_data.is_private
    await db.commit()
    # Announce change
    privacy_status = "privada" if room.is_private else "pública"
    announcement = {"type": "system", "content": f"La mesa ahora es {privacy_status}."}
    await manager.broadcast_to_room(json.dumps(announcement), room_name)
    return

@app.put("/rooms/{room_name}/rename", response_model=schemas.RoomOut)
async def rename_room(
    room_name: str,
    rename_data: schemas.RoomNameUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Room).filter(Room.name == room_name))
    room = result.scalar_one_or_none()
    if not room:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Room not found")
    if room.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only the room owner can rename it")

    new_name = rename_data.new_name
    result = await db.execute(select(Room).filter(Room.name == new_name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="New room name already exists")

    # Announce change before renaming
    announcement = {"type": "system", "content": f"La mesa ha sido renombrada de '{room.name}' a '{new_name}'."}
    await manager.broadcast_to_room(json.dumps(announcement), room.name)
    
    room.name = new_name
    await db.commit()
    await db.refresh(room)
    return room


#
# Admin & Moderation Endpoints
#
@app.post("/admin/ban/{username}", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def ban_user(username: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == username))
    user_to_ban = result.scalar_one_or_none()
    if not user_to_ban:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user_to_ban.is_banned = True
    await db.commit()
    return {"message": f"User {username} has been banned."}

@app.post("/admin/unban/{username}", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def unban_user(username: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter(User.username == username))
    user_to_unban = result.scalar_one_or_none()
    if not user_to_unban:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user_to_unban.is_banned = False
    await db.commit()
    return {"message": f"User {username} has been unbanned."}

#
# WebSocket Endpoint
#
@app.websocket("/ws/{room_name}")
async def websocket_endpoint(
    websocket: WebSocket, 
    room_name: str, 
    token: str = Query(...),
    db: AsyncSession = Depends(get_db)
):
    # Authenticate user via token
    user = await get_current_user(token, db)
    if not user or user.is_banned:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Check if room exists
    result = await db.execute(select(Room).filter(Room.name == room_name))
    room = result.scalar_one_or_none()
    if not room:
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Room not found")
        return

    # Authorize user for the room
    if user.current_room_id != room.id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="You must join the room first")
        return

    username = user.username
    await manager.connect(websocket, username, room_name)
    
    # Announce user joining
    join_message = {"type": "system", "content": f"User {username} has joined the room."}
    await manager.broadcast_to_room(json.dumps(join_message), room_name)

    try:
        while True:
            data = await websocket.receive_text()
            try:
                message_data = json.loads(data)
                msg_type = message_data.get("type")
                
                if msg_type == "room_message":
                    message_to_broadcast = {"type": "message", "sender": username, "content": message_data.get("content", "")}
                    await manager.broadcast_to_room(json.dumps(message_to_broadcast), room_name)
                
                elif msg_type == "private_message":
                    recipient = message_data.get("to")
                    if recipient:
                        pm_content = {"type": "private_message", "sender": username, "content": message_data.get("content", "")}
                        await manager.send_personal_message(json.dumps(pm_content), recipient)
                
                else:
                    # Handle unknown message types if necessary
                    pass

            except json.JSONDecodeError:
                # Handle non-JSON messages if necessary
                await manager.broadcast_to_room(f"[{username}]: {data}", room_name)

    except WebSocketDisconnect:
        manager.disconnect(websocket, username, room_name)
        # Announce user leaving
        leave_message = {"type": "system", "content": f"User {username} has left the room."}
        await manager.broadcast_to_room(json.dumps(leave_message), room_name)