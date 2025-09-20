from sqlalchemy import Column, Integer, String, Enum, Boolean, ForeignKey, Text, Table 
# Asegúrate de que 'Table' esté con mayúscula
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import enum

Base = declarative_base()

# --- TABLA DE ASOCIACIÓN PARA BANEOS (AÑADIDO) ---
# Esta tabla no es una clase, es una definición directa que conecta usuarios y mesas para registrar los baneos.
room_bans_table = Table('room_bans', Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('room_id', Integer, ForeignKey('rooms.id'), primary_key=True)
)

class UserRole(enum.Enum):
    COMMON_USER = "common_user"
    ROOM_LEADER = "room_leader"  # Owner of a room
    MODERATOR = "moderator"
    ADMIN = "admin"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.COMMON_USER, nullable=False)
    
    status_message = Column(String(255), default="Online")
    is_banned = Column(Boolean, default=False) # Este es el ban GLOBAL

    # Foreign Key to the room the user is currently in
    current_room_id = Column(Integer, ForeignKey("rooms.id"), nullable=True)
    
    # Relationships
    current_room = relationship("Room", back_populates="members", foreign_keys=[current_room_id])
    owned_rooms = relationship("Room", back_populates="owner", foreign_keys="Room.owner_id")

    # --- RELACIÓN DE BANEO (AÑADIDO) ---
    # Esto crea una lista `user.banned_from_rooms` que contiene todas las mesas de las que un usuario ha sido baneado.
    banned_from_rooms = relationship("Room", secondary=room_bans_table, back_populates="banned_users")

class Room(Base):
    __tablename__ = "rooms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    is_private = Column(Boolean, default=False)

    # Foreign Key to the user who owns the room
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    owner = relationship("User", back_populates="owned_rooms", foreign_keys=[owner_id])
    members = relationship("User", back_populates="current_room", foreign_keys=[User.current_room_id])

    # --- RELACIÓN DE BANEO (AÑADIDO) ---
    # Esto crea la "lista negra": `room.banned_users` contendrá todos los usuarios baneados de esta mesa.
    banned_users = relationship("User", secondary=room_bans_table, back_populates="banned_from_rooms")
