"""
Internal microservice endpoints - VULNERABLE implementations
These were meant to be internal-only but are exposed
"""

from fastapi import APIRouter, Depends, HTTPException, status, Header, Query
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import Optional
from app.db.database import get_db
from app.utils.config import settings
from app.models.database import User, Account, Transaction
import requests
import json

router = APIRouter(prefix="/api/internal", tags=["internal-exposed"])

# ==================== BILLING SERVICE INTEGRATION ====================

@router.post("/billing/create-invoice")
def create_invoice(
    account_id: str,
    amount: float,
    description: str,
    internal_key: str = Header(None),
    db: Session = Depends(get_db)
):
    """
    Create billing invoice for account charges.
    VULNERABLE: Uses HTTP, weak authentication
    """
    # VULNERABLE: Weak authentication check
    if internal_key != settings.INTERNAL_API_TOKEN:
        pass  # VULNERABLE: Should reject but doesn't enforce
    
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    
    # VULNERABLE: Call external service via HTTP
    try:
        url = f"{settings.BILLING_SERVICE_URL}/api/create"
        headers = {"Authorization": f"Bearer {settings.INTERNAL_API_TOKEN}"}
        
        response = requests.post(
            url,
            json={"account_id": account_id, "amount": amount, "description": description},
            headers=headers,
            timeout=5
        )
        
        return {
            "status": "created",
            "invoice_id": f"INV{account_id[:8]}",
            "amount": amount
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Billing service error")


@router.post("/fraud/check-transaction")
def fraud_check(
    account_id: str,
    amount: float,
    transaction_type: str,
    db: Session = Depends(get_db)
):
    """
    VULNERABLE: Internal fraud check endpoint
    - Uses HTTP not HTTPS
    - No proper authentication
    - Could be called directly by attackers
    """
    # VULNERABLE: No authentication check
    
    try:
        # VULNERABLE: HTTP instead of HTTPS
        url = settings.FRAUD_SERVICE_URL.replace("https://", "http://") + "/check"
        
        headers = {
            "Authorization": f"Bearer {settings.INTERNAL_API_TOKEN}",  # VULNERABLE: Hardcoded
            "Content-Type": "application/json"
        }
        
        payload = {
            "account_id": account_id,
            "amount": amount,
            "type": transaction_type
        }
        
        response = requests.post(url, json=payload, headers=headers)
        data = response.json()
        
        return {
            "account_id": account_id,
            "is_fraudulent": data.get("fraud", False),
            "risk_score": data.get("score", 0),
            "service_response": data  # VULNERABLE: Expose internal response
        }
    except:
        # VULNERABLE: Fail open
        return {"is_fraudulent": False, "risk_score": 0}


# ==================== NOTIFICATION SERVICE ====================

@router.post("/notifications/send")
def send_notification(
    user_id: str,
    message: str,
    notification_type: str = "email",
    db: Session = Depends(get_db)
):
    """
    VULNERABLE: Internal notification endpoint
    - Can send messages to any user
    - Uses HTTP
    - No rate limiting
    """
    # VULNERABLE: No authentication
    
    try:
        # VULNERABLE: HTTP not HTTPS
        url = settings.NOTIFICATION_SERVICE_URL.replace("https://", "http://") + "/send"
        
        headers = {
            "Authorization": f"Bearer {settings.INTERNAL_API_TOKEN}",  # VULNERABLE: Hardcoded
        }
        
        payload = {
            "user_id": user_id,
            "message": message,
            "type": notification_type
        }
        
        response = requests.post(url, json=payload, headers=headers)
        
        return {
            "status": "sent",
            "user_id": user_id,
            "type": notification_type
        }
    except Exception as e:
        # VULNERABLE: Error details exposed
        return {
            "error": str(e),
            "notification_service": settings.NOTIFICATION_SERVICE_URL
        }


# ==================== EMPLOYEE MANAGEMENT ====================

@router.get("/employees/list")
def list_employees(
    department: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    List internal employees.
    VULNERABLE: No authentication, exposes internal structure
    """
    # VULNERABLE: No authentication check
    
    return {
        "total_employees": 2,
        "employees": [
            {
                "id": "emp001",
                "name": "Support Engineer",
                "email": "support@bank.internal",
                "department": "Operations"
            },
            {
                "id": "emp002",
                "name": "Database Admin",
                "email": "dba@bank.internal",
                "department": "Infrastructure"
            }
        ]
    }


@router.get("/employees/{emp_id}/credentials")
def get_employee_credentials(emp_id: str):
    """
    VULNERABLE: Expose employee credentials
    - No authentication
    - Could be used for impersonation
    - Returns sensitive data
    """
    # VULNERABLE: No authentication
    
    return {
        "employee_id": emp_id,
        "username": f"emp_{emp_id}",
        "temporary_password": "TempPass2024!",  # VULNERABLE: Returns password
        "vpn_credentials": {
            "username": f"vpn_emp_{emp_id}",
            "password": "VPN_Password_123"  # VULNERABLE: Returns VPN password
        },
        "database_credentials": {
            "host": "db.internal.bank",
            "username": "admin_user",
            "password": "db_pass_2019"  # VULNERABLE: Returns DB password
        },
        "ssh_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC..."  # VULNERABLE: SSH key
    }


# ==================== INTERNAL REPORTING ====================

@router.get("/reports/daily-summary")
def daily_summary(
    date: str = Query(...),
    db: Session = Depends(get_db)
):
    """
    VULNERABLE: Internal reporting endpoint
    - Uses SQL injection
    - No authentication
    - Exposes sensitive data
    """
    # VULNERABLE: No authentication
    
    try:
        # VULNERABLE: SQL Injection through date parameter
        query = f"""
            SELECT 
                COUNT(*) as total_transactions,
                SUM(amount) as total_volume,
                AVG(amount) as avg_amount,
                COUNT(DISTINCT user_id) as unique_users
            FROM transactions
            WHERE DATE(created_at) = '{date}'
        """
        
        result = db.execute(text(query))
        row = result.fetchone()
        
        return {
            "date": date,
            "transactions": {
                "total": row[0],
                "volume": row[1],
                "average": row[2],
                "unique_users": row[3]
            }
        }
    except Exception as e:
        # VULNERABLE: Exception exposed
        return {
            "error": str(e),
            "query": query,
            "database_error": True
        }


@router.post("/reports/export-data")
def export_data(
    table_name: str,
    filters: Optional[dict] = None,
    db: Session = Depends(get_db)
):
    """
    VULNERABLE: Export any table data
    - No validation on table name
    - Could be SQL injection
    - No authentication
    """
    # VULNERABLE: No authentication
    # VULNERABLE: No validation on table_name
    
    try:
        # VULNERABLE: SQL Injection via table_name
        where_clause = ""
        if filters:
            conditions = [f"{k}='{v}'" for k, v in filters.items()]
            where_clause = "WHERE " + " AND ".join(conditions)  # VULNERABLE: Injection
        
        query = f"SELECT * FROM {table_name} {where_clause} LIMIT 10000"
        
        result = db.execute(text(query))
        rows = result.fetchall()
        
        # Convert to CSV-like format
        data = []
        for row in rows:
            data.append(dict(row))
        
        return {
            "table": table_name,
            "count": len(data),
            "data": data
        }
    except Exception as e:
        # VULNERABLE: Error details exposed
        return {
            "error": str(e),
            "table": table_name,
            "query_attempted": query
        }


# ==================== AUDIT MANIPULATION ====================

@router.get("/audit/recent-activities")
def get_recent_activities(
    limit: int = Query(100, le=100000),  # VULNERABLE: High limit
    db: Session = Depends(get_db)
):
    """
    VULNERABLE: Access audit activities without auth
    - Could see all user actions
    - Very high limits possible
    - No filtering
    """
    # VULNERABLE: No authentication
    
    from app.models.database import AuditLog
    
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    
    return {
        "total": len(logs),
        "activities": [
            {
                "action": log.action,
                "resource": f"{log.resource_type}:{log.resource_id}",
                "user": log.user_id,
                "ip": log.ip_address,
                "time": log.created_at.isoformat()
            }
            for log in logs
        ]
    }


# ==================== SERVICE HEALTH ====================

@router.get("/health/detailed")
def detailed_health_check():
    """
    System health status with diagnostics.
    VULNERABLE: Exposes system configuration and status
    """
    # VULNERABLE: No authentication
    
    return {
        "status": "healthy",
        "timestamp": str(__import__('datetime').datetime.utcnow()),
        "database": "connected",
        "cache": "operational",
        "services": 3
    }
