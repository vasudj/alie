"""
Sample data initialization script.
Run this to populate the database with test data.

Usage:
    python -m app.scripts.populate_db
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.db.database import SessionLocal, init_db
from app.models.database import User, Account, Transaction, Card, KYCDocument
from app.auth.jwt_handler import AuthHandler
from datetime import datetime, timedelta
import uuid

def populate_database():
    """Populate database with sample data."""
    
    # Initialize database tables
    init_db()
    db = SessionLocal()
    
    try:
        # Clear existing data (optional)
        print("Clearing existing data...")
        db.query(Transaction).delete()
        db.query(Card).delete()
        db.query(KYCDocument).delete()
        db.query(Account).delete()
        db.query(User).delete()
        db.commit()
        
        print("Creating sample users...")
        
        # Create sample users
        users_data = [
            {
                "email": "john.doe@example.com",
                "name": "John Doe",
                "phone": "+1-555-0001"
            },
            {
                "email": "jane.smith@example.com",
                "name": "Jane Smith",
                "phone": "+1-555-0002"
            },
            {
                "email": "bob.wilson@example.com",
                "name": "Bob Wilson",
                "phone": "+1-555-0003"
            },
            {
                "email": "alice.johnson@example.com",
                "name": "Alice Johnson",
                "phone": "+1-555-0004"
            },
            {
                "email": "admin@bank.local",
                "name": "Admin User",
                "phone": "+1-555-9999",
                "is_admin": True
            }
        ]
        
        users = []
        for user_data in users_data:
            user = User(
                email=user_data["email"],
                password_hash=AuthHandler.hash_password("password123"),
                full_name=user_data["name"],
                phone=user_data.get("phone"),
                is_admin=user_data.get("is_admin", False)
            )
            db.add(user)
            users.append(user)
        
        db.commit()
        print(f"Created {len(users)} users")
        
        print("Creating sample accounts...")
        
        # Create sample accounts
        accounts = []
        for i, user in enumerate(users):
            for j in range(2):
                account = Account(
                    user_id=user.id,
                    account_number=f"ACC{user.id[:8]}{j:02d}",
                    account_type="checking" if j == 0 else "savings",
                    balance=5000 + (i * 1000) + (j * 500),
                    overdraft_limit=1000 if j == 0 else 0,
                    iban=f"DE89370400440532{str(uuid.uuid4())[:10]}",
                )
                db.add(account)
                accounts.append(account)
        
        db.commit()
        print(f"Created {len(accounts)} accounts")
        
        print("Creating sample transactions...")
        
        # Create sample transactions
        transactions = []
        for i in range(10):
            from_account = accounts[i % len(accounts)]
            to_account = accounts[(i + 1) % len(accounts)]
            
            transaction = Transaction(
                user_id=from_account.user_id,
                account_id=from_account.id,
                transaction_type="transfer",
                amount=100 + (i * 50),
                recipient_account_id=to_account.id,
                description=f"Payment #{i+1}",
                status="completed",
                reference_number=f"TXN{str(uuid.uuid4())[:12]}"
            )
            db.add(transaction)
            transactions.append(transaction)
        
        db.commit()
        print(f"Created {len(transactions)} transactions")
        
        print("Creating sample cards...")
        
        # Create sample cards
        cards = []
        for account in accounts[:5]:
            card = Card(
                account_id=account.id,
                card_number="4532-1234-5678-9010",  # Sample Visa
                card_type="debit",
                cardholder_name=account.user.full_name,
                expiry_month=12,
                expiry_year=2026,
                cvv_hash="$2b$12$cvvhash",
                status="active",
                daily_limit=5000,
                is_blocked=False
            )
            db.add(card)
            cards.append(card)
        
        db.commit()
        print(f"Created {len(cards)} cards")
        
        print("Creating sample KYC documents...")
        
        # Create sample KYC documents
        kyc_docs = []
        for user in users[:3]:
            kyc_doc = KYCDocument(
                user_id=user.id,
                document_type="passport",
                document_id="AB123456",
                document_path="/uploads/kyc/passport_001.pdf",
                verification_status="verified",
                verified_at=datetime.utcnow(),
                verified_by="KYC_Officer_001"
            )
            db.add(kyc_doc)
            kyc_docs.append(kyc_doc)
        
        db.commit()
        print(f"Created {len(kyc_docs)} KYC documents")
        
        print("\n✓ Database population completed successfully!")
        print("\nSample credentials:")
        print("  Regular user: john.doe@example.com / password123")
        print("  Admin user:   admin@bank.local / password123")
        print("\nAPI Documentation: http://localhost:8000/api/docs")
        
    except Exception as e:
        db.rollback()
        print(f"✗ Error populating database: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    populate_database()
