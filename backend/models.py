from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from passlib.context import CryptContext
from datetime import datetime
import os

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="USER")  # ADMIN or USER
    credits = Column(Integer, default=0)

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.password_hash)


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(100), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=True)  # Allow NULL for URL analysis
    analysis_data = Column(JSON, nullable=False)  # Store full analysis result as JSON
    ai_analysis = Column(Text, nullable=True)  # Store AI analysis text
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(50), nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    user = relationship("User", backref="analyses")


class CreditPurchase(Base):
    __tablename__ = "credit_purchases"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Integer, nullable=False)  # Number of credits purchased
    balance_after = Column(Integer, nullable=False)  # User's credit balance after purchase
    purchased_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    user = relationship("User", backref="credit_purchases")


def get_db_engine():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL environment variable is required")
    
    # MySQL connection pool settings
    engine = create_engine(
        database_url,
        pool_pre_ping=True,  # Verify connections before using
        pool_recycle=3600,   # Recycle connections after 1 hour
        pool_size=10,
        max_overflow=20
    )
    return engine


def init_db():
    engine = get_db_engine()
    Base.metadata.create_all(bind=engine)

    # Seed initial data
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()

    try:
        # Check if admin exists
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                username="admin",
                password_hash=pwd_context.hash("admin123"),
                role="ADMIN",
                credits=999999
            )
            db.add(admin)

        # Check if user exists
        user = db.query(User).filter(User.username == "user").first()
        if not user:
            user = User(
                username="user",
                password_hash=pwd_context.hash("user123"),
                role="USER",
                credits=0
            )
            db.add(user)

        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_db():
    engine = get_db_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

