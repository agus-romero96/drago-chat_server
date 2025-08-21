from pydantic import BaseModel
from typing import Optional, List
from .models import UserRole

#
# Base Schemas
#
class UserBase(BaseModel):
    username: str

class RoomBase(BaseModel):
    name: str
    description: Optional[str] = None
    is_private: bool = False

#
# Token Schemas
#
class Token(BaseModel):
    access_token: str
    token_type: str

#
# User Schemas
#
class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    role: UserRole
    status_message: Optional[str]
    current_room_id: Optional[int] = None

    class Config:
        orm_mode = True

class StatusUpdate(BaseModel):
    status_message: str

#
# Room Schemas
#
class RoomCreate(RoomBase):
    pass

class RoomOut(RoomBase):
    id: int
    owner_id: int
    owner: UserOut # Nested schema to show owner details

    class Config:
        orm_mode = True

class RoomPrivacyUpdate(BaseModel):
    is_private: bool

class RoomNameUpdate(BaseModel):
    new_name: str
