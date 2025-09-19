import os
from dotenv import load_dotenv

load_dotenv() 

class Settings:
    # Database settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:%40123ar.2024@localhost/drago_chat_db")

    # JWT settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-super-secret-key") # CHANGE THIS IN PRODUCTION
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Server settings
    SERVER_HOST: str = os.getenv("SERVER_HOST", "0.0.0.0")
    SERVER_PORT: int = int(os.getenv("SERVER_PORT", 8000))

settings = Settings()
