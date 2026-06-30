"""
Legacy v1 API endpoints - VULNERABLE implementations
Contains various security flaws for ALIE detection:
- Broken authentication
- Missing rate limiting
- SQL injection
- Verbose error messages
- Mass assignment
- Insecure internal calls
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Header
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional, Dict, List
import json
import requests
from app.db.database import get_db
from app.utils.config import settings
from app.models.database import User, Account, Transaction, Card
from app.services.service import (
    UserService, AccountService, TransactionService,
    AdminService, NotificationService, FraudService
)
from app.models.schemas import (
    UserUpdateRaw, AccountUpdateLegacy, QuickPayRequest,
    DebugAccountResponse, ErrorResponseVerbose, AdminDashboardData
)

router = APIRouter(prefix="/api/v1", tags=["v1-legacy-vulnerable"])

# ==================== AUTHENTICATION VULNERABILITIES ====================

@router.post("/auth/login-legacy")
def login_legacy(email: str, password: str, db: Session = Depends(get_db)):
    """
    Legacy login endpoint - older authentication system
    VULNERABLE: No rate limiting, basic validation
    """
    try:
        user = UserService.get_user_by_email(db, email)
        
        if not user:
            # VULNERABLE: Timing attack possible
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        if user.password_hash != password:  # VULNERABLE: Comparing plaintext!
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # VULNERABLE: Returns user object with sensitive data
        return {
            "user_id": user.id,
            "email": user.email,
            "is_admin": user.is_admin,
            "token": "legacy-token-" + user.id[:8],
            "session_valid_for_hours": 24
        }
    except Exception as e:
        # VULNERABLE: Exposes exception details
        raise HTTPException(
            status_code=500,
            detail="Authentication service error"
        )


@router.get("/auth/check-email")
def check_email_exists(email: str):
    """
    Check if email is registered in the system.
    VULNERABLE: No authentication required - user enumeration
    """
    # VULNERABLE: No auth check - anyone can enumerate users
    return {
        "email": email,
        "status": "registered" if email.endswith("@example.com") else "available"
    }


@router.get("/debug/user/{user_id}")
def debug_get_user(user_id: str, db: Session = Depends(get_db)):
    """
    Internal debug endpoint for user information lookup.
    Used by support team for debugging user issues.
    VULNERABLE: No authentication required, returns internal fields
    """
    user = UserService.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # VULNERABLE: Returns all internal fields without filtering
    return {
        "id": user.id,
        "email": user.email,
        "password_hash": user.password_hash,  # VULNERABLE!
        "full_name": user.full_name,
        "is_admin": user.is_admin,
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "created_at": user.created_at.isoformat()
    }


# ==================== SQL INJECTION VULNERABILITIES ====================

@router.get("/export/search")
def search_transactions_sql_injection(
    query: str,
    db: Session = Depends(get_db)
):
    """
    Search transactions by description or reference number.
    VULNERABLE: Uses raw SQL concatenation, allowing SQL injection
    """
    try:
        # VULNERABLE: SQL Injection - no parameterization
        sql_query = f"""
            SELECT * FROM transactions 
            WHERE description LIKE '%{query}%' 
            OR reference_number = '{query}'
            LIMIT 1000
        """
        
        result = db.execute(text(sql_query))
        transactions = result.fetchall()
        
        return {
            "found": len(transactions),
            "results": [dict(row) for row in transactions]
        }
    except Exception as e:
        # VULNERABLE: Exposes SQL error to attacker
        raise HTTPException(status_code=400, detail="Invalid search query")


@router.post("/export/user-data")
def export_user_data(user_id: str, db: Session = Depends(get_db)):
    """
    Export all user account data. Admin endpoint.
    VULNERABLE: No authentication, SQL injection in user_id
    """
    try:
        # VULNERABLE: SQL Injection
        query = f"SELECT * FROM users WHERE id = '{user_id}'"
        result = db.execute(text(query))
        user_data = result.fetchone()
        
        if user_data:
            query2 = f"SELECT * FROM accounts WHERE user_id = '{user_id}'"
            result2 = db.execute(text(query2))
            accounts = result2.fetchall()
        else:
            accounts = []
        
        return {
            "user": dict(user_data) if user_data else None,
            "accounts": [dict(a) for a in accounts],
            "export_status": "success"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail="Export failed")


@router.get("/admin/users/search")
def admin_search_users(
    email_pattern: str = Query(...),
    role: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Search for users by email pattern.
    VULNERABLE: SQL injection in search parameters
    """
    try:
        # VULNERABLE: SQL Injection through email_pattern
        base_query = f"SELECT * FROM users WHERE email LIKE '%{email_pattern}%'"
        
        if role:
            # VULNERABLE: Additional injection point
            base_query += f" AND role = '{role}'"
        
        result = db.execute(text(base_query))
        users = result.fetchall()
        
        return {
            "users": [{"id": u[0], "email": u[1], "name": u[2]} for u in users],
            "count": len(users)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail="Search failed")


# ==================== MASS ASSIGNMENT VULNERABILITIES ====================

@router.post("/account/update")
def update_account_mass_assignment(
    account_id: str,
    updates: Dict,  # VULNERABLE: Raw dict accepted
    db: Session = Depends(get_db)
):
    """
    Update account information.
    VULNERABLE: Accepts arbitrary fields, mass assignment
    """
    try:
        account = db.query(Account).filter(Account.id == account_id).first()
        if not account:
            raise HTTPException(status_code=404, detail="Account not found")
        
        # VULNERABLE: Blind update of all fields
        for key, value in updates.items():
            if hasattr(account, key):
                setattr(account, key, value)  # Allows is_admin, balance, etc.
        
        db.commit()
        return {
            "status": "success",
            "account_id": account.id,
            "updated_fields": list(updates.keys())
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail="Update failed")


@router.post("/user/update")
def update_user_mass_assignment(
    user_id: str,
    data: UserUpdateRaw,  # VULNERABLE: Raw schema with extra="allow"
    db: Session = Depends(get_db)
):
    """
    Update user profile information.
    VULNERABLE: Accepts any fields, users can set is_admin, role, balance
    """
    user = UserService.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # VULNERABLE: Updates all fields including sensitive ones
    update_data = data.dict(exclude_unset=True)
    
    for field, value in update_data.items():
        if hasattr(user, field):
            setattr(user, field, value)  # Allows setting is_admin, role, etc!
    
    db.commit()
    return {
        "status": "success",
        "user_id": user.id,
        "updated": list(update_data.keys())
    }


# ==================== MISSING RATE LIMITING ====================

@router.post("/otp/request")
def request_otp(email: str):
    """
    Request one-time password for email verification.
    VULNERABLE: No rate limiting, no throttling
    """
    # VULNERABLE: No rate limiting or throttling
    # VULNERABLE: No authentication
    
    return {
        "status": "sent",
        "message": f"OTP sent to {email}",
        "retry_after_seconds": 60
    }


@router.post("/password/reset")
def reset_password(email: str, new_password: str):
    """
    Reset user password without verification.
    VULNERABLE: No rate limiting, accepts any password
    """
    # VULNERABLE: No rate limiting
    # VULNERABLE: Allows password reset without verification
    
    return {
        "status": "success",
        "message": f"Password reset for {email}",
        "next_action": "Login with new password"
    }


# ==================== QUICK PAY (ZOMBIE API) ====================

@router.post("/quick-pay")
def quick_pay(request: QuickPayRequest, db: Session = Depends(get_db)):
    """
    Quick payment transfer between accounts.
    VULNERABLE: No rate limiting, minimal validation
    """
    try:
        # VULNERABLE: No rate limiting check
        # VULNERABLE: Minimal validation
        
        from_account = db.query(Account).filter(Account.id == request.account_id).first()
        to_account = db.query(Account).filter(Account.id == request.recipient_id).first()
        
        if not from_account or not to_account:
            raise HTTPException(status_code=404, detail="Account not found")
        
        if from_account.balance < request.amount:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        
        # VULNERABLE: Transaction without proper fraud check
        is_fraud = FraudService.check_fraud(
            request.account_id,
            request.amount,
            "quick_pay"
        )
        
        if is_fraud:
            raise HTTPException(status_code=400, detail="Transaction blocked")
        
        # Perform transfer
        from_account.balance -= request.amount
        to_account.balance += request.amount
        
        transaction = Transaction(
            user_id=from_account.user_id,
            account_id=from_account.id,
            transaction_type="quick_pay",
            amount=request.amount,
            recipient_account_id=to_account.id,
            description=request.description,
            txn_metadata=json.dumps(request.metadata) if request.metadata else None,
            reference_number=f"QP{str(uuid.uuid4())[:16]}"
        )
        
        db.add(transaction)
        db.commit()
        
        # VULNERABLE: Uses HTTP for notification
        NotificationService.send_notification(
            to_account.user_id,
            f"You received {request.amount} via quick-pay",
            "sms"
        )
        
        return {
            "status": "success",
            "transaction_id": transaction.id,
            "reference": transaction.reference_number
        }
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Transfer failed")


# ==================== INTERNAL ENDPOINTS (ACCIDENTALLY EXPOSED) ====================

@router.get("/internal/system/status")
def system_status():
    """
    System status endpoint for monitoring.
    VULNERABLE: Reveals internal system information
    """
    return {
        "status": "operational",
        "uptime_hours": 168,
        "database": "PostgreSQL",
        "cache_enabled": True,
        "timestamp": str(__import__('datetime').datetime.utcnow())
    }


@router.get("/internal/accounts/all")
def get_all_accounts_internal(
    api_key: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    List all accounts in the system.
    VULNERABLE: Minimal authentication check, lists all accounts
    """
    # VULNERABLE: Simple header check instead of proper auth
    if api_key != settings.INTERNAL_API_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    accounts = AdminService.get_all_accounts(db)
    
    return {
        "total": len(accounts),
        "accounts": [
            {
                "id": a.id,
                "account_number": a.account_number,
                "balance": a.balance,
                "status": a.status
            }
            for a in accounts
        ]
    }


# ==================== VERBOSE ERROR RESPONSES ====================

@router.get("/legacy/error-test")
def test_error_response():
    """
    Error handling test endpoint.
    """
    try:
        result = 1 / 0  # Trigger exception
    except Exception as e:
        import traceback
        return {
            "error": "Division error",
            "traceback": traceback.format_exc()
        }


# ==================== DEPRECATED ZOMBIE ENDPOINTS ====================

@router.get("/beta/quick-balance/{account_id}")
def beta_get_balance(account_id: str, db: Session = Depends(get_db)):
    """
    Quick balance check endpoint (Beta API).
    VULNERABLE: No authentication required
    """
    # VULNERABLE: No authentication
    account = db.query(Account).filter(Account.id == account_id).first()
    
    if not account:
        return {
            "found": False,
            "message": "Account not found"
        }
    
    return {
        "found": True,
        "account_id": account.id,
        "balance": account.balance,
        "type": account.account_type,
        "status": account.status
    }


@router.post("/legacy/csv-export")
def export_csv(user_id: str, db: Session = Depends(get_db)):
    """
    Export user transaction history as CSV.
    VULNERABLE: SQL injection, no authentication
    """
    try:
        # VULNERABLE: SQL Injection
        query = f"""
            SELECT u.id, u.email, a.account_number, a.balance, t.amount, t.created_at
            FROM users u
            LEFT JOIN accounts a ON u.id = a.user_id
            LEFT JOIN transactions t ON a.id = t.account_id
            WHERE u.id = '{user_id}'
        """
        
        result = db.execute(text(query))
        rows = result.fetchall()
        
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        for row in rows:
            writer.writerow(row)
        
        return {
            "status": "success",
            "format": "csv",
            "data": output.getvalue()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail="Export failed")


import uuid


# ==================== ZOMBIE API TRAP (Payload Volatility Bait) ====================

def _build_bloated_ledger_payload(num_entries: int = 500) -> dict:
    """Generate a deliberately massive ledger payload (50 KB+) to bait AI anomaly detection."""
    entries = []
    base_ts = 1_700_000_000
    for i in range(num_entries):
        entries.append({
            "ledger_entry_id": f"LGR-{uuid.uuid4().hex}",
            "transaction_ref":  f"TXN-{uuid.uuid4().hex}",
            "batch_sequence":   i + 1,
            "account_debit":    f"ACC-{uuid.uuid4().hex[:12]}",
            "account_credit":   f"ACC-{uuid.uuid4().hex[:12]}",
            "amount_cents":     random.randint(100, 10_000_000),
            "currency":         random.choice(["USD", "EUR", "GBP", "JPY", "INR", "SGD"]),
            "value_date":       f"2023-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
            "posting_date":     f"2023-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
            "gl_account_code":  f"GL-{random.randint(10000, 99999)}",
            "cost_centre":      f"CC-{random.randint(100, 999)}",
            "narrative":        f"Batch posting for legacy reconciliation job ref {uuid.uuid4().hex}",
            "status":           random.choice(["POSTED", "PENDING", "REVERSED", "FAILED"]),
            "authorised_by":    f"OPS-USER-{random.randint(1, 50):03d}",
            "system_timestamp": base_ts + i * 60,
            "checksum":         uuid.uuid4().hex,
            "padding_field_a":  "X" * 32,
            "padding_field_b":  "Y" * 32,
            "padding_field_c":  "Z" * 16,
            "legacy_flags":     {"eod_processed": True, "archived": False, "migrated": False,
                                 "reconciled": random.choice([True, False])},
        })
    return {
        "report_name":   "Legacy General Ledger Batch Export",
        "report_version": "v1.0-DEPRECATED",
        "generated_at":  "2023-11-01T02:00:00Z",
        "generated_by":  "batch-scheduler/legacy-cron",
        "warning":       "This report endpoint is unmaintained. Migrate to /api/v2/reports/ledger.",
        "total_entries": len(entries),
        "entries":       entries,
    }


@router.get("/reports/legacy-ledger")
def zombie_legacy_ledger():
    """
    ZOMBIE API TRAP — Legacy general-ledger batch export.

    This endpoint was part of a nightly reconciliation job that was
    decommissioned in 2022. It was never removed from the codebase.
    It intentionally returns a 50 KB+ bloated JSON payload so that
    Level 1 AI can detect abnormal Payload Volatility in batch data.

    Detection signals:
      - Massive response payload (>>50 KB) on a GET with no auth
      - No client-side caching headers
      - Endpoint path matches deprecated v1 pattern
      - High response size vs. zero request body
    """
    import random as _random  # already imported at top; re-alias for clarity in scope
    payload = _build_bloated_ledger_payload(num_entries=600)
    return payload
