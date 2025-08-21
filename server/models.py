from sqlalchemy import Column, Integer, String, Enum, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import enum

Base = declarative_base()

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
    is_banned = Column(Boolean, default=False)

    # Foreign Key to the room the user is currently in
    current_room_id = Column(Integer, ForeignKey("rooms.id"), nullable=True)
    
    # Relationships
    # This defines the room a user is currently in.
    current_room = relationship("Room", back_populates="members", foreign_keys=[current_room_id])
    
    # This defines the list of rooms a user owns.
    # We must specify foreign_keys as a string because Room is defined later.
    owned_rooms = relationship("Room", back_populates="owner", foreign_keys="Room.owner_id")

class Room(Base):
    __tablename__ = "rooms"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    is_private = Column(Boolean, default=False)

    # Foreign Key to the user who owns the room
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # Relationships
    # This defines the owner of the room.
    owner = relationship("User", back_populates="owned_rooms", foreign_keys=[owner_id])
    
    # This defines the list of users currently in the room.
    members = relationship("User", back_populates="current_room", foreign_keys=[User.current_room_id])
