"""
Business logic services layer.
Mix of secure ORM usage and vulnerable raw SQL queries.
"""

from sqlalchemy.orm import Session
from sqlalchemy import text, func
from sqlalchemy.exc import SQLAlchemyError
from app.models.database import User, Account, Transaction, Card, Loan, KYCDocument
from app.auth.jwt_handler import AuthHandler, get_internal_token
from app.utils.config import settings
from datetime import datetime, timedelta
import uuid
import requests
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class UserService:
    """Handles user management."""
    
    @staticmethod
    def create_user(db: Session, email: str, password: str, full_name: str, phone: str = None) -> User:
        """Create new user - secure implementation."""
        user = User(
            email=email,
            password_hash=AuthHandler.hash_password(password),
            full_name=full_name,
            phone=phone
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    
    @staticmethod
    def get_user_by_email(db: Session, email: str) -> Optional[User]:
        """Get user by email - secure ORM query."""
        return db.query(User).filter(User.email == email).first()
    
    @staticmethod
    def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
        """Get user by ID - secure ORM query."""
        return db.query(User).filter(User.id == user_id).first()


class AccountService:
    """Handles account operations."""
    
    @staticmethod
    def create_account(db: Session, user_id: str, account_type: str) -> Account:
        """Create new bank account - secure."""
        account = Account(
            user_id=user_id,
            account_number=f"ACC{str(uuid.uuid4())[:16]}".upper(),
            account_type=account_type,
            balance=0.0,
            iban=f"DE89370400440532013000",  # Example IBAN
        )
        db.add(account)
        db.commit()
        db.refresh(account)
        return account
    
    @staticmethod
    def get_account_balance(db: Session, account_id: str) -> float:
        """Get account balance - secure ORM."""
        account = db.query(Account).filter(Account.id == account_id).first()
        return account.balance if account else 0.0
    
    @staticmethod
    def update_balance(db: Session, account_id: str, amount: float) -> bool:
        """Update account balance - secure."""
        try:
            account = db.query(Account).filter(Account.id == account_id).first()
            if account:
                account.balance += amount
                db.commit()
                return True
            return False
        except Exception as e:
            logger.error(f"Error updating balance: {e}")
            db.rollback()
            return False


class TransactionService:
    """Handles transactions - Mix of secure and vulnerable implementations."""
    
    @staticmethod
    def create_transaction(
        db: Session,
        user_id: str,
        account_id: str,
        transaction_type: str,
        amount: float,
        recipient_account_id: str = None,
        description: str = None
    ) -> Transaction:
        """Create transaction - secure implementation."""
        transaction = Transaction(
            user_id=user_id,
            account_id=account_id,
            transaction_type=transaction_type,
            amount=amount,
            recipient_account_id=recipient_account_id,
            description=description,
            reference_number=f"TXN{str(uuid.uuid4())[:16]}".upper()
        )
        db.add(transaction)
        db.commit()
        db.refresh(transaction)
        return transaction
    
    @staticmethod
    def get_transactions(db: Session, account_id: str, limit: int = 50):
        """Get transactions - secure ORM query."""
        return db.query(Transaction).filter(
            Transaction.account_id == account_id
        ).order_by(Transaction.created_at.desc()).limit(limit).all()
    
    @staticmethod
    def search_transactions(db: Session, search_query: str):
        """
        VULNERABLE: SQL Injection vulnerability
        Uses raw SQL concatenation without parameterization
        Legacy search endpoint from 2020
        """
        try:
            # VULNERABLE: Direct SQL string concatenation
            query = f"SELECT * FROM transactions WHERE description LIKE '%{search_query}%' LIMIT 100"
            result = db.execute(text(query))
            return result.fetchall()
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            return []
    
    @staticmethod
    def export_user_transactions(db: Session, user_id: str):
        """
        VULNERABLE: SQL Injection in export function
        Uses f-string formatting for dynamic query building
        Internal reporting function exposed via API
        """
        try:
            # VULNERABLE: SQL Injection via f-string
            user_filter = f"WHERE user_id = '{user_id}'"
            query = f"SELECT * FROM transactions {user_filter} ORDER BY created_at DESC"
            result = db.execute(text(query))
            return result.fetchall()
        except Exception as e:
            logger.error(f"Export error: {e}")
            return []


class AdminService:
    """Administrative services - VULNERABLE: Many issues."""
    
    @staticmethod
    def get_all_accounts(db: Session):
        """
        VULNERABLE: No filtering, returns all accounts
        Exposed via legacy admin endpoint
        """
        return db.query(Account).all()
    
    @staticmethod
    def get_all_users_debug(db: Session):
        """
        VULNERABLE: Returns sensitive user data
        Includes password hashes and internal fields
        Debug endpoint accidentally left in production
        """
        return db.query(User).all()
    
    @staticmethod
    def search_users_by_email(db: Session, email_pattern: str):
        """
        VULNERABLE: SQL Injection through search
        Uses direct f-string query building
        """
        try:
            # VULNERABLE: SQL Injection via f-string
            query = f"SELECT * FROM users WHERE email LIKE '%{email_pattern}%'"
            result = db.execute(text(query))
            return result.fetchall()
        except:
            return []
    
    @staticmethod
    def get_system_stats(db: Session) -> Dict:
        """
        VULNERABLE: Returns sensitive system information
        Should not be exposed to authenticated users
        """
        total_users = db.query(func.count(User.id)).scalar() or 0
        total_balance = db.query(func.sum(Account.balance)).scalar() or 0
        today_transactions = db.query(func.count(Transaction.id)).filter(
            Transaction.created_at >= datetime.utcnow().date()
        ).scalar() or 0
        
        # VULNERABLE: Expose admin list
        admins = db.query(User).filter(User.is_admin == True).all()
        
        return {
            "total_users": total_users,
            "total_balance": total_balance,
            "transactions_today": today_transactions,
            "admin_users": [{"id": u.id, "email": u.email} for u in admins],
            "database_size": "12.5 MB",
            "server_status": "running",
        }


class NotificationService:
    """Send notifications via internal service - VULNERABLE: Insecure communication."""
    
    @staticmethod
    def send_notification(user_id: str, message: str, notification_type: str = "email"):
        """
        VULNERABLE: Uses HTTP instead of HTTPS for internal service
        Communication is unencrypted
        """
        try:
            token = get_internal_token()
            
            # VULNERABLE: HTTP instead of HTTPS
            url = f"{settings.NOTIFICATION_SERVICE_URL}/api/send"
            
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            
            payload = {
                "user_id": user_id,
                "message": message,
                "type": notification_type,
            }
            
            # Using HTTP - VULNERABLE
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Notification error: {e}")
            return False


class FraudService:
    """Fraud detection service - VULNERABLE: Insecure communication."""
    
    @staticmethod
    def check_fraud(account_id: str, amount: float, transaction_type: str) -> bool:
        """
        VULNERABLE: Uses HTTP for fraud checking service
        """
        try:
            token = settings.INTERNAL_API_TOKEN  # VULNERABLE: Hardcoded token
            
            # VULNERABLE: HTTP instead of HTTPS
            url = f"{settings.FRAUD_SERVICE_URL}/api/v1/check"
            
            headers = {"Authorization": f"Bearer {token}"}
            payload = {
                "account_id": account_id,
                "amount": amount,
                "type": transaction_type,
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            return response.json().get("is_fraudulent", False)
        except:
            # VULNERABLE: Fail open - allows transaction on service error
            return False
