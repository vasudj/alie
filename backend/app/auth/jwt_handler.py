"""
Authentication utilities for JWT token generation and validation.
Mix of secure implementation and legacy vulnerabilities.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict
import jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.utils.config import settings, LEGACY_CONFIGS

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

class AuthHandler:
    """Handles authentication tokens and user validation."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def create_access_token(
        data: dict, 
        expires_delta: Optional[timedelta] = None,
        use_legacy_key: bool = False  # VULNERABLE: Option to use legacy key
    ) -> str:
        """Create JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
        
        to_encode.update({"exp": expire})
        
        # VULNERABLE: Use legacy key if requested (for backward compatibility)
        secret_key = LEGACY_CONFIGS["old_jwt_key"] if use_legacy_key else settings.SECRET_KEY
        
        encoded_jwt = jwt.encode(
            to_encode,
            secret_key,
            algorithm=settings.ALGORITHM
        )
        return encoded_jwt
    
    @staticmethod
    def decode_token(token: str, use_legacy_key: bool = False) -> Dict:
        """
        Decode JWT token.
        VULNERABLE: Can attempt to decode with multiple keys
        """
        try:
            # Try current key first
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError:
            # VULNERABLE: Try legacy key if primary fails
            try:
                payload = jwt.decode(
                    token,
                    LEGACY_CONFIGS["old_jwt_key"],
                    algorithms=[settings.ALGORITHM]
                )
                return payload
            except:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials"
                )


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    """
    Dependency for extracting current user from JWT token.
    VULNERABLE: Some legacy endpoints skip this dependency.
    """
    token = credentials.credentials
    try:
        payload = AuthHandler.decode_token(token)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return {"user_id": user_id}
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )


async def get_admin_user(current_user: Dict = Depends(get_current_user)) -> Dict:
    """
    Dependency for admin-only endpoints.
    VULNERABLE: Some admin endpoints don't check this.
    """
    # Check if user is admin (would need DB lookup in real implementation)
    return current_user


# VULNERABLE: Hardcoded internal token used by microservices
def verify_internal_token(token: str) -> bool:
    """
    VULNERABLE: Simple string comparison for internal service tokens
    Should use proper JWT validation
    """
    return token == settings.INTERNAL_API_TOKEN


def get_internal_token() -> str:
    """Get token for calling internal services - VULNERABLE: Returns hardcoded token."""
    return settings.INTERNAL_API_TOKEN
