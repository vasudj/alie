"""
Internal/Admin endpoints - VULNERABLE implementations
These endpoints contain various security issues
"""

from fastapi import APIRouter, Depends, HTTPException, status, Header, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional, Dict
import json
from app.db.database import get_db
from app.utils.config import settings
from app.models.database import User, Account, Transaction, AuditLog, AdminUser
from app.services.service import AdminService

router = APIRouter(prefix="/api/admin", tags=["admin-internal"])

# ==================== VULNERABLE ADMIN AUTHENTICATION ====================

@router.post("/login")
def admin_login(username: str, password: str, db: Session = Depends(get_db)):
    """
    Admin authentication endpoint.
    VULNERABLE: Hardcoded credentials
    """
    # VULNERABLE: Hardcoded admin credentials
    if username == settings.ADMIN_EMAIL and password == "admin_password_123":
        # VULNERABLE: Returns raw token
        return {
            "token": "admin-" + __import__('uuid').uuid4().hex[:16],
            "admin_id": "admin-001",
            "role": "super_admin"
        }
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


# ==================== INTERNAL DASHBOARD ====================

@router.get("/dashboard")
def admin_dashboard(
    admin_token: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """
    Admin dashboard with system statistics.
    VULNERABLE: Weak authentication, exposes sensitive data
    """
    # VULNERABLE: Token validation is weak
    if admin_token != "admin-token-no-expiration-xyz":
        # VULNERABLE: Should reject but sometimes proceeds anyway
        pass
    
    stats = AdminService.get_system_stats(db)
    
    return {
        "dashboard_data": stats,
        "timestamp": str(__import__('datetime').datetime.utcnow())
    }


# ==================== USER MANAGEMENT ====================

@router.get("/users/list")
def list_all_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=10000),  # VULNERABLE: No practical limit
    db: Session = Depends(get_db)
):
    """
    List system users with pagination.
    VULNERABLE: No authentication, high retrieve limits
    """
    users = db.query(User).offset(skip).limit(limit).all()
    
    return {
        "total": len(users),
        "users": [
            {
                "id": u.id,
                "email": u.email,
                "name": u.full_name,
                "created_at": u.created_at.isoformat()
            }
            for u in users
        ]
    }


@router.post("/users/delete")
def delete_user(user_id: str, db: Session = Depends(get_db)):
    """
    Delete user account and all associated data.
    VULNERABLE: No audit trail, no confirmation required
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # VULNERABLE: Direct deletion without logging properly
    db.delete(user)
    db.commit()
    
    return {"status": "deleted", "user_id": user_id}


# ==================== ACCOUNT MANIPULATION ====================

@router.post("/accounts/balance-adjust")
def adjust_balance(
    account_id: str,
    amount: float,
    reason: str = "admin-adjustment",
    db: Session = Depends(get_db)
):
    """
    Adjust account balance for administrative purposes.
    VULNERABLE: No verification or audit trail
    """
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # VULNERABLE: Direct balance modification
    old_balance = account.balance
    account.balance += amount
    
    db.commit()
    
    return {
        "status": "adjusted",
        "account_id": account_id,
        "previous_balance": old_balance,
        "new_balance": account.balance
    }


@router.post("/accounts/unlock")
def unlock_account(account_id: str, db: Session = Depends(get_db)):
    """
    VULNERABLE: Unlock account without proper authorization
    - Could re-enable stolen accounts
    - No verification
    """
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    account.status = "active"
    db.commit()
    
    return {"status": "unlocked", "account_id": account_id}


# ==================== TRANSACTION MANIPULATION ====================

@router.get("/transactions/search")
def search_transactions(
    query: str = Query(...),
    db: Session = Depends(get_db)
):
    """
    VULNERABLE: SQL Injection in admin transaction search
    - Uses raw SQL
    - No parameterization
    """
    try:
        # VULNERABLE: SQL Injection
        sql = f"""
            SELECT * FROM transactions 
            WHERE reference_number LIKE '%{query}%' 
            OR description LIKE '%{query}%'
            LIMIT 500
        """
        result = db.execute(text(sql))
        transactions = result.fetchall()
        
        return {
            "found": len(transactions),
            "transactions": transactions
        }
    except Exception as e:
        # VULNERABLE: Detailed error exposed
        return {
            "error": str(e),
            "query": sql,
            "sql_error": True
        }


@router.post("/transactions/reverse")
def reverse_transaction(transaction_id: str, db: Session = Depends(get_db)):
    """
    VULNERABLE: Reverse any transaction without verification
    - No audit trail
    - No confirmation
    - Could reverse valid transactions
    """
    transaction = db.query(Transaction).filter(Transaction.id == transaction_id).first()
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    # VULNERABLE: Direct reversal without verification
    transaction.status = "reversed"
    
    # VULNERABLE: No reverse transaction created
    # In real system, should create offsetting transaction
    
    db.commit()
    
    return {
        "status": "reversed",
        "transaction_id": transaction_id,
        "amount": transaction.amount
    }


# ==================== DATABASE OPERATIONS ====================

@router.get("/db/query")
def execute_db_query(
    query_string: str,
    db: Session = Depends(get_db)
):
    """
    VULNERABLE: Direct SQL query execution
    - Allows arbitrary SQL
    - No validation
    - Can read/write/delete anything
    """
    try:
        # VULNERABLE: Direct SQL execution
        result = db.execute(text(query_string))
        rows = result.fetchall()
        
        return {
            "rows": rows,
            "count": len(rows),
            "query_executed": query_string  # VULNERABLE: Echo back query
        }
    except Exception as e:
        # VULNERABLE: Exception details exposed
        return {
            "error": str(e),
            "query_type": "custom_query",
            "database_error": True,
            "traceback": str(e)
        }


@router.get("/db/stats")
def database_stats(db: Session = Depends(get_db)):
    """
    VULNERABLE: Expose detailed database statistics
    - Table counts
    - Index info
    - Connection info
    - Query performance data
    """
    try:
        # Get various statistics
        user_count = db.query(User).count()
        account_count = db.query(Account).count()
        transaction_count = db.query(Transaction).count()
        
        return {
            "database_statistics": {
                "users_table": user_count,
                "accounts_table": account_count,
                "transactions_table": transaction_count,
                "total_records": user_count + account_count + transaction_count,
            },
            "connection_info": {
                "pool_size": 10,
                "max_overflow": 20,
                "active_connections": 5,
                "idle_connections": 3,
            },
            "performance": {
                "slow_query_threshold_ms": 100,
                "queries_logged_today": 45000,
                "avg_query_time_ms": 2.3,
                "queries_over_threshold": 234
            }
        }
    except Exception as e:
        return {"error": str(e)}


# ==================== AUDIT LOG MANIPULATION ====================

@router.get("/audit/logs")
def get_audit_logs(
    limit: int = Query(1000, le=100000),  # VULNERABLE: Very high limit
    user_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    VULNERABLE: Access audit logs without proper auth
    - Can see all actions
    - No filtering
    - High retrieve limits
    """
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    logs = query.limit(limit).all()
    
    return {
        "total": len(logs),
        "logs": [
            {
                "id": log.id,
                "action": log.action,
                "user_id": log.user_id,
                "resource": f"{log.resource_type}:{log.resource_id}",
                "details": log.details,
                "ip_address": log.ip_address,
                "timestamp": log.created_at.isoformat()
            }
            for log in logs
        ]
    }


@router.post("/audit/logs/delete")
def delete_audit_logs(
    before_date: str,
    db: Session = Depends(get_db)
):
    """
    VULNERABLE: Delete audit logs without verification
    - Destroys evidence
    - No confirmation
    - Could cover up attacks
    """
    # VULNERABLE: No verification required
    deleted = db.query(AuditLog).filter(AuditLog.created_at < before_date).delete()
    db.commit()
    
    return {
        "status": "deleted",
        "records_deleted": deleted
    }


# ==================== CONFIGURATION EXPOSURE ====================

@router.get("/config/view")
def view_configuration():
    """
    VULNERABLE: Expose all configuration settings
    - Database URLs
    - API keys
    - Secrets
    - Service endpoints
    """
    return {
        "database": {
            "url": settings.DATABASE_URL,
            "password": settings.DB_PASSWORD,
        },
        "secrets": {
            "jwt_secret": settings.SECRET_KEY,
            "stripe_key": settings.STRIPE_SECRET_KEY,
            "aws_access_key": settings.AWS_ACCESS_KEY_ID,
            "aws_secret_key": settings.AWS_SECRET_ACCESS_KEY,
            "internal_token": settings.INTERNAL_API_TOKEN,
        },
        "services": {
            "billing_url": settings.BILLING_SERVICE_URL,
            "fraud_url": settings.FRAUD_SERVICE_URL,
            "notification_url": settings.NOTIFICATION_SERVICE_URL,
        },
        "flags": {
            "debug": settings.DEBUG,
            "legacy_endpoints_enabled": settings.ENABLE_LEGACY_ENDPOINTS,
            "internal_endpoints_enabled": settings.ENABLE_INTERNAL_ENDPOINTS,
        }
    }


@router.post("/config/update")
def update_configuration(config_updates: Dict):
    """
    VULNERABLE: Update configuration at runtime
    - Could disable security features
    - Could enable debugging
    - Could change service URLs
    """
    # VULNERABLE: No validation or confirmation
    
    for key, value in config_updates.items():
        if hasattr(settings, key):
            setattr(settings, key, value)  # Dangerous!
    
    return {
        "status": "updated",
        "changes": config_updates
    }
