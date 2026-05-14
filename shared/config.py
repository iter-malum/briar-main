from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    DB_USER: str = Field(default="briar")
    DB_PASSWORD: str = Field(default="secure_password_change_me")
    DB_HOST: str = Field(default="postgres")
    DB_PORT: str = Field(default="5432")
    DB_NAME: str = Field(default="briar_db")
    
    RABBITMQ_HOST: str = Field(default="rabbitmq")
    RABBITMQ_PORT: str = Field(default="5672")
    RABBITMQ_USER: str = Field(default="guest")
    RABBITMQ_PASS: str = Field(default="guest")
    
    JWT_SECRET: str = Field(default="super_secret_key_for_development_only")
    JWT_ALGORITHM: str = Field(default="HS256")
    ORCHESTRATOR_URL: str = Field(default="http://orchestrator:8000")

    @property
    def db_url(self) -> str:
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    @property
    def rabbitmq_url(self) -> str:
        return f"amqp://{self.RABBITMQ_USER}:{self.RABBITMQ_PASS}@{self.RABBITMQ_HOST}:{self.RABBITMQ_PORT}/"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()