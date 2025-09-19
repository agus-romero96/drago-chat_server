import json
from typing import List
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Query
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import func

from .database import create_db_and_tables, get_db, AsyncSessionLocal
from .models import User, UserRole, Room
from .auth import (
    get_password_hash, verify_password, create_access_token, 
    get_current_active_user, require_role, get_current_user
)
from .websocket_manager import manager
from . import schemas

app = FastAPI(title="DragoChat Server")

LOBBY_ROOM_NAME = "__LOBBY__"

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
    # Comprobar si ya existe una sala con ese nombre
    result = await db.execute(select(Room).filter(Room.name == room_data.name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El nombre de la sala ya existe")

    # Crear la nueva sala
    new_room = Room(**room_data.dict(), owner_id=current_user.id)
    db.add(new_room)
    
    # --- LA CORRECCIÓN CLAVE ESTÁ AQUÍ ---
    # En lugar de asignar solo el ID, manejamos la relación directamente.
    # Esto asegura que SQLAlchemy entienda que el usuario es un miembro de la sala.
    new_room.members.append(current_user)
    
    # Hacemos el commit para que la transacción sea visible para todos
    await db.commit()
    
    # Refrescamos los objetos para obtener su estado final desde la BD
    await db.refresh(new_room)
    await db.refresh(new_room, attribute_names=['owner'])

    return new_room

@app.get("/rooms", response_model=List[schemas.RoomOut])
async def list_public_rooms(db: AsyncSession = Depends(get_db)):
    query = (
        select(Room)
        .filter_by(is_private=False)
        .options(selectinload(Room.owner))
    )
    result = await db.execute(query)
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
    room_id = current_user.current_room_id
    if room_id is None:
        return current_user

    result = await db.execute(select(Room).filter(Room.id == room_id))
    room_to_leave = result.scalar_one_or_none()

    current_user.current_room_id = None
    await db.commit()
    await db.refresh(current_user)

    if room_to_leave:
        is_owner_leaving = room_to_leave.owner_id == current_user.id
        result = await db.execute(select(func.count(User.id)).where(User.current_room_id == room_to_leave.id))
        user_count = result.scalar()

        if user_count == 0:
            await db.delete(room_to_leave)
            await db.commit()
        elif is_owner_leaving:
            result = await db.execute(select(User).where(User.current_room_id == room_to_leave.id).limit(1))
            new_owner = result.scalar_one_or_none()
            if new_owner:
                room_to_leave.owner_id = new_owner.id
                await db.commit()
                owner_announcement = {"type": "system", "event": "owner_change", "new_owner": new_owner.username, "content": f"{new_owner.username} es ahora el nuevo jefe de la mesa."}
                await manager.broadcast_to_room(json.dumps(owner_announcement), room_to_leave.name)

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

    announcement = {"type": "system", "content": f"La mesa ha sido renombrada de '{room.name}' a '{new_name}'."}
    await manager.broadcast_to_room(json.dumps(announcement), room.name)
    
    room.name = new_name
    await db.commit()
    await db.refresh(room)
    return room

@app.get("/rooms/{room_name}/members")
async def get_room_members(
    room_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(Room).where(Room.name == room_name))
    room = result.scalar_one_or_none()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    if current_user.current_room_id != room.id:
        raise HTTPException(status_code=403, detail="You are not in this room")

    result = await db.execute(select(User.username).where(User.current_room_id == room.id))
    members = [row[0] for row in result.all()]

    owner_result = await db.execute(select(User.username).where(User.id == room.owner_id))
    owner_username = owner_result.scalar_one_or_none()
    if owner_username and owner_username in members:
        members.remove(owner_username)
        members.insert(0, f"{owner_username} (Jefe de mesa)")

    return {"room": room.name, "count": len(members), "members": members}

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
async def handle_websocket_text_data(data: str, sender_username: str, room_name: str, websocket: WebSocket):
    """Procesa únicamente mensajes de texto (JSON) recibidos."""
    try:
        message_data = json.loads(data)
        msg_type = message_data.get("type")

        # Mensajes de control para la transmisión de voz
        if msg_type in ["voice_start", "voice_end"]:
            message_to_broadcast = {"type": msg_type, "sender": sender_username}
            await manager.broadcast_to_room(json.dumps(message_to_broadcast), room_name, exclude_websocket=websocket)

        # Mensaje de texto normal a la sala
        elif msg_type == "room_message":
            content = message_data.get("content", "")
            message_to_broadcast = {"type": "message", "sender": sender_username, "content": content}
            await manager.broadcast_to_room(json.dumps(message_to_broadcast), room_name)
        
        # Mensaje privado
        elif msg_type == "private_message":
            recipient = message_data.get("to")
            content = message_data.get("content", "")
            if recipient:
                pm_to_recipient = {"type": "private_message", "sender": sender_username, "content": content}
                await manager.send_personal_message(json.dumps(pm_to_recipient), recipient)
                
                pm_to_sender = {"type": "private_message", "sender": "Tú", "to": recipient, "content": content}
                await manager.send_personal_message(json.dumps(pm_to_sender), sender_username)

    except (json.JSONDecodeError, AttributeError):
        # Fallback para texto plano que no es JSON
        message_to_broadcast = {"type": "message", "sender": sender_username, "content": data}
        await manager.broadcast_to_room(json.dumps(message_to_broadcast), room_name)

@app.websocket("/ws/lobby")
async def websocket_lobby(
    websocket: WebSocket,
    token: str = Query(...),
    is_returning: bool = Query(False),
    db: AsyncSession = Depends(get_db)
):
    user = await get_current_user(token, db)
    if not user or user.is_banned:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    username = user.username
    is_first_connection = not is_returning

    await manager.connect(websocket, username, LOBBY_ROOM_NAME)
    
    if is_first_connection:
        join_message = {"type": "system", "content": f"{username} se ha conectado al servidor."}
        await manager.broadcast_to_all(json.dumps(join_message), exclude_websocket=websocket)

    try:
        while True:
            data = await websocket.receive_text()
            await handle_websocket_text_data(data, username, LOBBY_ROOM_NAME, websocket)

    except WebSocketDisconnect:
        manager.disconnect(websocket, username, LOBBY_ROOM_NAME)
        if not getattr(websocket, 'is_switching', False):
            leave_message = {"type": "system", "content": f"{username} se ha desconectado del servidor."}
            await manager.broadcast_to_all(json.dumps(leave_message))

@app.websocket("/ws/{room_name}")
async def websocket_endpoint(
    room_name: str,
    websocket: WebSocket,
    token: str = Query(...),
    db: AsyncSession = Depends(get_db)
):
    user = await get_current_user(token, db)
    if not user or user.is_banned:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    result = await db.execute(select(Room).filter(Room.name == room_name))
    room = result.scalar_one_or_none()
    if not room or user.current_room_id != room.id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Room not found or user not joined")
        return

    username = user.username
    await manager.connect(websocket, username, room_name)
    
    join_message = {"type": "system", "content": f"{username} se ha unido a la mesa."}
    await manager.broadcast_to_room(json.dumps(join_message), room_name, exclude_websocket=websocket)

    try:
        # Bucle principal que acepta tanto texto como binarios
        while True:
            message = await websocket.receive()

            if message["type"] == "websocket.disconnect":
                break

            if "text" in message:
                await handle_websocket_text_data(message["text"], username, room_name, websocket)
            
            elif "bytes" in message:
                await manager.broadcast_binary_to_room(message["bytes"], room_name, exclude_websocket=websocket)

    finally:
        # Lógica de limpieza que se ejecuta siempre al desconectar
        manager.disconnect(websocket, username, room_name)
        
        leave_message = {"type": "system", "content": f"{username} ha abandonado la mesa."}
        await manager.broadcast_to_room(json.dumps(leave_message), room_name)

        if not getattr(websocket, 'is_switching', False):
            global_leave_message = {"type": "system", "content": f"{username} se ha desconectado del servidor."}
            await manager.broadcast_to_all(json.dumps(global_leave_message))

            if room:
                # Usamos una nueva sesión para la limpieza para evitar problemas de "detached instance"
                async with AsyncSessionLocal() as session:
                    user_to_update = await session.get(User, user.id)
                    if user_to_update:
                        user_to_update.current_room_id = None
                        await session.commit()
                    
                    room_to_check = await session.get(Room, room.id)
                    if room_to_check:
                        is_owner_leaving = room_to_check.owner_id == user.id
                        result = await session.execute(select(func.count(User.id)).where(User.current_room_id == room_to_check.id))
                        user_count = result.scalar()

                        if user_count == 0:
                            await session.delete(room_to_check)
                            await session.commit()
                        elif is_owner_leaving:
                            res = await session.execute(select(User).where(User.current_room_id == room_to_check.id).limit(1))
                            new_owner = res.scalar_one_or_none()
                            if new_owner:
                                room_to_check.owner_id = new_owner.id
                                await session.commit()
                                announcement = {"type": "system", "event": "owner_change", "new_owner": new_owner.username, "content": f"{new_owner.username} es ahora el nuevo jefe de la mesa."}
                                await manager.broadcast_to_room(json.dumps(announcement), room_to_check.name)