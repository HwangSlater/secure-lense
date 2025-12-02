from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
import os

Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="USER")  # ADMIN or USER
    credits = Column(Integer, default=0)

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.password_hash)


def get_db_engine():
    database_url = os.getenv("DATABASE_URL", "sqlite:///./securelens.db")
    if database_url.startswith("sqlite"):
        engine = create_engine(database_url, connect_args={"check_same_thread": False})
    else:
        engine = create_engine(database_url)
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

