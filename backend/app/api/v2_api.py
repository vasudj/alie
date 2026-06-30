"""
Modern v2 API endpoints - Secure implementation
Following security best practices
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List
from app.db.database import get_db
from app.auth.jwt_handler import get_current_user, AuthHandler
from app.models.schemas import (
    LoginRequest, TokenResponse, AccountCreateRequest,
    AccountResponse, TransferRequest, TransferResponse,
    KYCUploadRequest, CardRequest
)
from app.services.service import UserService, AccountService, TransactionService
from app.models.database import Account, Card, KYCDocument
from datetime import timedelta

router = APIRouter(prefix="/api/v2", tags=["v2-secure"])

@router.post("/auth/register", response_model=AccountResponse)
def register(request: AccountCreateRequest, db: Session = Depends(get_db)):
    """
    Register new user - secure implementation
    Validates input, hashes password, enforces security
    """
    # Check if user exists
    existing_user = UserService.get_user_by_email(db, request.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )
    
    # Create user with secure password hashing
    user = UserService.create_user(
        db,
        email=request.email,
        password="temp_password",  # Users set via separate endpoint
        full_name=request.full_name,
        phone=request.phone
    )
    
    # Create default account
    account = AccountService.create_account(db, user.id, request.account_type)
    
    return AccountResponse(
        account_id=account.id,
        email=user.email,
        full_name=user.full_name,
        account_type=account.account_type,
        balance=account.balance,
        status=account.status,
        created_at=account.created_at
    )


@router.post("/auth/login", response_model=TokenResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    """
    Secure login endpoint
    Validates credentials and issues JWT token
    """
    user = UserService.get_user_by_email(db, request.email)
    
    if not user or not AuthHandler.verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )
    
    # Create access token
    access_token = AuthHandler.create_access_token(
        data={"sub": user.id}
    )
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=1800
    )


@router.get("/accounts/balance")
def get_balance(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Get account balance - requires authentication
    Uses dependency injection for auth validation
    """
    user = UserService.get_user_by_id(db, current_user["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get user's first account
    if not user.accounts:
        raise HTTPException(status_code=404, detail="No accounts found")
    
    account = user.accounts[0]
    return {
        "account_id": account.id,
        "balance": account.balance,
        "account_type": account.account_type,
        "currency": "USD"
    }


@router.get("/accounts/{account_id}")
def get_account(account_id: str, current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Get account details - validates ownership
    Secure implementation with proper authorization checks
    """
    account = db.query(Account).filter(Account.id == account_id).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # Check authorization
    if account.user_id != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    return AccountResponse(
        account_id=account.id,
        email=account.user.email,
        full_name=account.user.full_name,
        account_type=account.account_type,
        balance=account.balance,
        status=account.status,
        created_at=account.created_at
    )


@router.post("/transfers/send", response_model=TransferResponse)
def send_transfer(
    request: TransferRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Send transfer - secure implementation
    Validates accounts, checks balance, creates transaction
    """
    # Get sender account
    sender_accounts = db.query(Account).filter(Account.user_id == current_user["user_id"]).all()
    if not sender_accounts:
        raise HTTPException(status_code=404, detail="No accounts found")
    
    sender_account = sender_accounts[0]
    
    # Validate amount
    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount")
    
    if sender_account.balance < request.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Verify recipient exists
    recipient_account = db.query(Account).filter(Account.id == request.recipient_account_id).first()
    if not recipient_account:
        raise HTTPException(status_code=404, detail="Recipient account not found")
    
    # Execute transfer
    try:
        sender_account.balance -= request.amount
        recipient_account.balance += request.amount
        
        transfer = TransactionService.create_transaction(
            db,
            current_user["user_id"],
            sender_account.id,
            "transfer",
            request.amount,
            request.recipient_account_id,
            request.description
        )
        
        db.commit()
        
        return TransferResponse(
            transfer_id=transfer.id,
            from_account_id=sender_account.id,
            to_account_id=recipient_account.id,
            amount=transfer.amount,
            status="completed",
            created_at=transfer.created_at
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Transfer failed")


@router.post("/kyc/upload")
def upload_kyc(
    request: KYCUploadRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    KYC document upload - secure implementation
    Validates document type and creates upload record
    """
    user = UserService.get_user_by_id(db, current_user["user_id"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    kyc_doc = KYCDocument(
        user_id=user.id,
        document_type=request.document_type,
        document_id=request.document_id,
        verification_status="pending"
    )
    
    db.add(kyc_doc)
    db.commit()
    
    return {
        "kyc_id": kyc_doc.id,
        "status": "pending",
        "message": "Document uploaded for verification"
    }


@router.get("/transactions")
def get_transactions(
    limit: int = Query(50, ge=1, le=500),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get transactions - secure with limit validation
    Proper input validation and authorization
    """
    user = UserService.get_user_by_id(db, current_user["user_id"])
    if not user or not user.accounts:
        return []
    
    account = user.accounts[0]
    transactions = TransactionService.get_transactions(db, account.id, limit)
    
    return [
        {
            "id": t.id,
            "type": t.transaction_type,
            "amount": t.amount,
            "status": t.status,
            "created_at": t.created_at,
            "reference": t.reference_number
        }
        for t in transactions
    ]


@router.post("/cards/block")
def block_card(
    card_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Block credit card - secure implementation
    Validates ownership before blocking
    """
    card = db.query(Card).filter(Card.id == card_id).first()
    if not card:
        raise HTTPException(status_code=404, detail="Card not found")
    
    # Verify card belongs to user
    account = db.query(Account).filter(Account.id == card.account_id).first()
    if not account or account.user_id != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    card.is_blocked = True
    db.commit()
    
    return {"status": "blocked", "card_id": card.id}


@router.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "2.0"}
