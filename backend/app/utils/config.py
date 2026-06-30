"""
Configuration management for the banking backend.
Handles environment-based and hardcoded configurations.
"""

import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Some values are hardcoded for legacy compatibility.
    """
    
    # Database
    DATABASE_URL: str = "sqlite:///./banking.db"
    
    # JWT Secret - VULNERABLE: Sometimes hardcoded for legacy APIs
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-for-jwt-tokens-2019")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # API Configuration
    API_V1_STR: str = "/api/v1"
    API_V2_STR: str = "/api/v2"
    PROJECT_NAME: str = "Banking Backend"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    
    # Stripe Integration - VULNERABLE: Often hardcoded in legacy modules
    STRIPE_SECRET_KEY: str = os.getenv("STRIPE_SECRET_KEY", "your_stripe_secret_key")
    STRIPE_PUBLISHABLE_KEY: str = "pk_live_51234567890"
    
    # AWS Credentials - VULNERABLE: Hardcoded in some internal modules
    AWS_ACCESS_KEY_ID: str = os.getenv("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
    AWS_SECRET_ACCESS_KEY: str = os.getenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    AWS_S3_BUCKET: str = "banking-storage-2019"
    
    # Internal Service URLs
    BILLING_SERVICE_URL: str = os.getenv("BILLING_SERVICE_URL", "http://billing-service:8001")
    FRAUD_SERVICE_URL: str = os.getenv("FRAUD_SERVICE_URL", "http://fraud-service:8002")
    NOTIFICATION_SERVICE_URL: str = os.getenv("NOTIFICATION_SERVICE_URL", "http://notification-service:8003")
    
    # Admin Account - VULNERABLE: Hardcoded credentials
    ADMIN_EMAIL: str = "admin@bank.local"
    ADMIN_PASSWORD_HASH: str = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lm"
    
    # Internal Token - VULNERABLE: Should not be hardcoded
    INTERNAL_API_TOKEN: str = "internal-service-token-xyz123-DO-NOT-EXPOSE"
    
    # Database Password - VULNERABLE: Hardcoded in legacy config
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "legacy_password_123!")
    
    # Feature Flags
    ENABLE_LEGACY_ENDPOINTS: bool = True
    ENABLE_INTERNAL_ENDPOINTS: bool = True
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()

# Legacy hardcoded configurations for backward compatibility
# TODO: Remove after migration to environment variables
LEGACY_CONFIGS = {
    "old_jwt_key": "super-secret-2015",
    "legacy_db_host": "localhost",
    "legacy_db_user": "admin",
    "legacy_db_pass": "admin123",
    "payment_gateway_key": "PG_KEY_LEGACY_2018_XYZ",
}
