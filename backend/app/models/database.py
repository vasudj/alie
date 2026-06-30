"""
SQLAlchemy ORM models for banking backend.
"""

from sqlalchemy import Column, String, Float, Integer, DateTime, Boolean, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.db.database import Base


class User(Base):
    """User account model."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    phone = Column(String(20), nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    role = Column(String(50), default="customer")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    accounts = relationship("Account", back_populates="user")
    transactions = relationship("Transaction", back_populates="user")
    kyc_documents = relationship("KYCDocument", back_populates="user")
    
    __table_args__ = (
        Index("idx_email_created", "email", "created_at"),
    )


class Account(Base):
    """Bank account model."""
    __tablename__ = "accounts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    account_number = Column(String(50), unique=True, nullable=False, index=True)
    account_type = Column(String(50), nullable=False)  # savings, checking, business
    balance = Column(Float, default=0.0)
    overdraft_limit = Column(Float, default=0.0)
    status = Column(String(50), default="active")
    iban = Column(String(100), nullable=True)
    swift_code = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="accounts")
    transactions = relationship("Transaction", back_populates="account")
    
    __table_args__ = (
        Index("idx_account_number_user", "account_number", "user_id"),
    )


class Transaction(Base):
    """Transaction history."""
    __tablename__ = "transactions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    account_id = Column(String(36), ForeignKey("accounts.id"), nullable=False, index=True)
    transaction_type = Column(String(50), nullable=False)  # transfer, payment, deposit, withdrawal
    amount = Column(Float, nullable=False)
    recipient_account_id = Column(String(36), nullable=True)
    description = Column(String(500), nullable=True)
    status = Column(String(50), default="completed")
    reference_number = Column(String(100), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    txn_metadata = Column("metadata", Text, nullable=True)  # JSON stored as text
    
    # Relationships
    user = relationship("User", back_populates="transactions")
    account = relationship("Account", back_populates="transactions")


class Card(Base):
    """Credit/Debit card model."""
    __tablename__ = "cards"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id = Column(String(36), ForeignKey("accounts.id"), nullable=False, index=True)
    card_number = Column(String(255), nullable=False)  # Encrypted in production
    card_type = Column(String(50), nullable=False)  # debit, credit
    cardholder_name = Column(String(255), nullable=False)
    expiry_month = Column(Integer, nullable=False)
    expiry_year = Column(Integer, nullable=False)
    cvv_hash = Column(String(255), nullable=False)
    status = Column(String(50), default="active")
    daily_limit = Column(Float, default=5000.0)
    is_blocked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class Loan(Base):
    """Loan products model."""
    __tablename__ = "loans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id = Column(String(36), ForeignKey("accounts.id"), nullable=False, index=True)
    amount = Column(Float, nullable=False)
    interest_rate = Column(Float, nullable=False)
    duration_months = Column(Integer, nullable=False)
    monthly_payment = Column(Float, nullable=False)
    remaining_balance = Column(Float, nullable=False)
    status = Column(String(50), default="approved")
    created_at = Column(DateTime, default=datetime.utcnow)
    next_payment_due = Column(DateTime, nullable=True)


class KYCDocument(Base):
    """KYC verification documents."""
    __tablename__ = "kyc_documents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    document_type = Column(String(50), nullable=False)  # passport, license, id_card
    document_id = Column(String(100), nullable=False)
    document_path = Column(String(500), nullable=True)
    verification_status = Column(String(50), default="pending")
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    verified_by = Column(String(100), nullable=True)
    
    # Relationships
    user = relationship("User", back_populates="kyc_documents")


class AuditLog(Base):
    """Internal audit logging."""
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    action = Column(String(255), nullable=False)
    user_id = Column(String(36), nullable=True, index=True)
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)  # JSON details
    ip_address = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class AdminUser(Base):
    """Admin user accounts with elevated privileges."""
    __tablename__ = "admin_users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, unique=True)
    role = Column(String(100), nullable=False)  # admin, moderator, support
    permissions = Column(Text, nullable=False)  # JSON array of permissions
    last_login = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
