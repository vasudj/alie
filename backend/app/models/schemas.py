"""
Pydantic schemas for request/response validation.
Mix of secure schemas and vulnerable ones with mass assignment.
"""

from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional
from enum import Enum

# ==================== SECURE SCHEMAS (v2) ====================

class AccountCreateRequest(BaseModel):
    """Secure schema with strict field validation."""
    email: EmailStr
    full_name: str
    phone: str
    account_type: str = Field(..., pattern="^(savings|checking|business)$")

class AccountResponse(BaseModel):
    """Secure response schema."""
    account_id: str
    email: str
    full_name: str
    account_type: str
    balance: float
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

class TransferRequest(BaseModel):
    """Secure transfer schema."""
    recipient_account_id: str
    amount: float = Field(..., gt=0, le=1000000)
    description: Optional[str] = None

class TransferResponse(BaseModel):
    """Secure transfer response."""
    transfer_id: str
    from_account_id: str
    to_account_id: str
    amount: float
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    """Secure login schema."""
    email: EmailStr
    password: str = Field(..., min_length=8)

class TokenResponse(BaseModel):
    """Token response schema."""
    access_token: str
    token_type: str
    expires_in: int

class KYCUploadRequest(BaseModel):
    """KYC verification request."""
    document_type: str = Field(..., pattern="^(passport|license|id_card)$")
    document_id: str

class CardRequest(BaseModel):
    """Credit card operations."""
    card_type: str = Field(..., pattern="^(debit|credit)$")
    card_limit: Optional[float] = None


# ==================== VULNERABLE SCHEMAS (v1 - Legacy) ====================

class UserUpdateRaw(BaseModel):
    """
    VULNERABLE: Mass assignment vulnerability
    Accepts any field and blindly updates the model.
    Users can set their own role, is_admin, balance, etc.
    """
    email: Optional[str] = None
    full_name: Optional[str] = None
    phone: Optional[str] = None
    balance: Optional[float] = None
    is_admin: Optional[bool] = None
    role: Optional[str] = None
    account_status: Optional[str] = None
    internal_notes: Optional[str] = None
    
    class Config:
        extra = "allow"  # VULNERABLE: Accept any extra fields


class AccountUpdateLegacy(BaseModel):
    """
    VULNERABLE: No field restrictions
    Allows updating sensitive fields that shouldn't be user-modifiable
    """
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    balance: Optional[float] = None
    overdraft_limit: Optional[float] = None
    is_active: Optional[bool] = None
    account_tier: Optional[str] = None
    
    class Config:
        extra = "allow"


class QuickPayRequest(BaseModel):
    """
    VULNERABLE: Minimal validation, accepts raw data
    Legacy quick-pay API from 2020 rollout
    """
    account_id: str
    recipient_id: str
    amount: float
    description: Optional[str] = None
    metadata: Optional[dict] = None  # VULNERABLE: Raw dict acceptance


class DebugAccountResponse(BaseModel):
    """
    VULNERABLE: Exposes internal fields
    Legacy debug endpoint includes sensitive information
    """
    id: str
    email: str
    password_hash: str  # VULNERABLE: Exposing password hash
    balance: float
    last_login: Optional[str] = None
    is_admin: bool
    internal_status: str
    db_id: int
    api_key: Optional[str] = None  # VULNERABLE: API keys in response


class ErrorResponseVerbose(BaseModel):
    """
    VULNERABLE: Verbose error responses with stack traces
    Legacy error handling exposes too much information
    """
    error: str
    code: int
    details: str  # VULNERABLE: Can contain stack traces
    database_error: Optional[str] = None  # VULNERABLE: DB errors exposed
    file_path: Optional[str] = None  # VULNERABLE: Filesystem paths
    query_params: Optional[dict] = None  # VULNERABLE: Parameters exposed


class AdminDashboardData(BaseModel):
    """
    VULNERABLE: Internal admin endpoint response
    Exposes raw database records without filtering
    """
    total_users: int
    total_balance: float
    transactions_today: int
    failed_logins: list
    admin_users: list  # VULNERABLE: Lists all admins
    database_size: str
    server_status: str


# ==================== PAYMENT SCHEMAS ====================

class PaymentIntentRequest(BaseModel):
    """Stripe payment intent."""
    amount: float
    currency: str = "usd"
    account_id: str
    description: Optional[str] = None
    metadata: Optional[dict] = None


class LoanApplicationRequest(BaseModel):
    """Loan application."""
    amount: float = Field(..., gt=0, le=500000)
    duration_months: int = Field(..., ge=6, le=360)
    purpose: str
    employment_status: str


class NotificationPreferences(BaseModel):
    """User notification preferences."""
    email_notifications: bool = True
    sms_notifications: bool = False
    in_app_notifications: bool = True
    fraud_alerts: bool = True
