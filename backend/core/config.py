"""
Configuration module for the SENTRIX LIVE++ platform.
Loads environment variables and provides configuration objects for different components.
"""
import os
from typing import List, Optional, Dict, Any
from pydantic import BaseSettings, Field, validator


class DatabaseSettings(BaseSettings):
    """Database connection settings."""
    POSTGRES_USER: str = Field(..., env="POSTGRES_USER")
    POSTGRES_PASSWORD: str = Field(..., env="POSTGRES_PASSWORD")
    POSTGRES_DB: str = Field(..., env="POSTGRES_DB")
    POSTGRES_HOST: str = Field(..., env="POSTGRES_HOST")
    POSTGRES_PORT: int = Field(5432, env="POSTGRES_PORT")
    
    @property
    def connection_string(self) -> str:
        """Get the PostgreSQL connection string."""
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"


class ElasticsearchSettings(BaseSettings):
    """Elasticsearch connection settings."""
    ELASTICSEARCH_HOST: str = Field(..., env="ELASTICSEARCH_HOST")
    ELASTICSEARCH_PORT: int = Field(9200, env="ELASTICSEARCH_PORT")
    ELASTICSEARCH_USERNAME: Optional[str] = Field(None, env="ELASTICSEARCH_USERNAME")
    ELASTICSEARCH_PASSWORD: Optional[str] = Field(None, env="ELASTICSEARCH_PASSWORD")
    
    @property
    def hosts(self) -> List[str]:
        """Get the Elasticsearch hosts."""
        return [f"http://{self.ELASTICSEARCH_HOST}:{self.ELASTICSEARCH_PORT}"]
    
    @property
    def auth(self) -> Optional[tuple]:
        """Get the Elasticsearch authentication tuple."""
        if self.ELASTICSEARCH_USERNAME and self.ELASTICSEARCH_PASSWORD:
            return (self.ELASTICSEARCH_USERNAME, self.ELASTICSEARCH_PASSWORD)
        return None


class KafkaSettings(BaseSettings):
    """Kafka connection and topic settings."""
    KAFKA_BOOTSTRAP_SERVERS: str = Field(..., env="KAFKA_BOOTSTRAP_SERVERS")
    KAFKA_TOPIC_NETWORK: str = Field("sentrix-network", env="KAFKA_TOPIC_NETWORK")
    KAFKA_TOPIC_AUTH: str = Field("sentrix-auth", env="KAFKA_TOPIC_AUTH")
    KAFKA_TOPIC_APP: str = Field("sentrix-app", env="KAFKA_TOPIC_APP")
    KAFKA_TOPIC_EDR: str = Field("sentrix-edr", env="KAFKA_TOPIC_EDR")
    
    @property
    def consumer_config(self) -> Dict[str, Any]:
        """Get the Kafka consumer configuration."""
        return {
            "bootstrap.servers": self.KAFKA_BOOTSTRAP_SERVERS,
            "group.id": "sentrix-consumer-group",
            "auto.offset.reset": "earliest"
        }
    
    @property
    def producer_config(self) -> Dict[str, Any]:
        """Get the Kafka producer configuration."""
        return {
            "bootstrap.servers": self.KAFKA_BOOTSTRAP_SERVERS
        }


class MinioSettings(BaseSettings):
    """MinIO/S3 connection settings."""
    MINIO_ROOT_USER: str = Field(..., env="MINIO_ROOT_USER")
    MINIO_ROOT_PASSWORD: str = Field(..., env="MINIO_ROOT_PASSWORD")
    MINIO_HOST: str = Field(..., env="MINIO_HOST")
    MINIO_PORT: int = Field(9000, env="MINIO_PORT")
    MINIO_BUCKET_PCAPS: str = Field("sentrix-pcaps", env="MINIO_BUCKET_PCAPS")
    MINIO_BUCKET_ARTIFACTS: str = Field("sentrix-artifacts", env="MINIO_BUCKET_ARTIFACTS")
    
    @property
    def endpoint(self) -> str:
        """Get the MinIO endpoint."""
        return f"{self.MINIO_HOST}:{self.MINIO_PORT}"


class RedisSettings(BaseSettings):
    """Redis connection settings."""
    REDIS_HOST: str = Field(..., env="REDIS_HOST")
    REDIS_PORT: int = Field(6379, env="REDIS_PORT")
    REDIS_PASSWORD: Optional[str] = Field(None, env="REDIS_PASSWORD")
    
    @property
    def connection_string(self) -> str:
        """Get the Redis connection string."""
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/0"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"


class JWTSettings(BaseSettings):
    """JWT authentication settings."""
    JWT_SECRET_KEY: str = Field(..., env="JWT_SECRET_KEY")
    JWT_ALGORITHM: str = Field("HS256", env="JWT_ALGORITHM")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(30, env="JWT_ACCESS_TOKEN_EXPIRE_MINUTES")


class LLMSettings(BaseSettings):
    """LLM provider settings."""
    LLM_PROVIDER: str = Field("openai", env="LLM_PROVIDER")
    OPENAI_API_KEY: Optional[str] = Field(None, env="OPENAI_API_KEY")
    ANTHROPIC_API_KEY: Optional[str] = Field(None, env="ANTHROPIC_API_KEY")
    
    @validator("LLM_PROVIDER")
    def validate_provider(cls, v):
        """Validate the LLM provider."""
        allowed_providers = ["openai", "anthropic"]
        if v not in allowed_providers:
            raise ValueError(f"LLM_PROVIDER must be one of {allowed_providers}")
        return v


class APISettings(BaseSettings):
    """API server settings."""
    API_HOST: str = Field("0.0.0.0", env="API_HOST")
    API_PORT: int = Field(8000, env="API_PORT")
    CORS_ORIGINS: List[str] = Field(["http://localhost:3000"], env="CORS_ORIGINS")
    
    @validator("CORS_ORIGINS", pre=True)
    def parse_cors_origins(cls, v):
        """Parse the CORS origins from a comma-separated string."""
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v


class Settings(BaseSettings):
    """Main settings class that combines all component settings."""
    # Component settings
    db: DatabaseSettings = DatabaseSettings()
    es: ElasticsearchSettings = ElasticsearchSettings()
    kafka: KafkaSettings = KafkaSettings()
    minio: MinioSettings = MinioSettings()
    redis: RedisSettings = RedisSettings()
    jwt: JWTSettings = JWTSettings()
    llm: LLMSettings = LLMSettings()
    api: APISettings = APISettings()
    
    # Application settings
    DEBUG: bool = Field(False, env="DEBUG")
    ENVIRONMENT: str = Field("production", env="ENVIRONMENT")
    
    class Config:
        """Pydantic configuration."""
        env_file = ".env"
        env_file_encoding = "utf-8"


# Create a global settings instance
settings = Settings()