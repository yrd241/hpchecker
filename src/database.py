# -*- coding: utf-8 -*-
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, JSON, Integer, ARRAY
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, UTC
import os
from dotenv import load_dotenv

load_dotenv()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sniper:sniper@localhost1:5432/sniper_db")

# Create SQLAlchemy engine
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class HoneypotRecord(Base):
    __tablename__ = "honeypots"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_address = Column(String(42), unique=True, nullable=False)
    is_honeypot = Column(Boolean, nullable=False)
    reasons = Column(ARRAY(Integer), nullable=False, default=[0])  # 0 means not a honeypot, otherwise stores reason numbers
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))

# Create tables
def init_db():
    Base.metadata.create_all(bind=engine)

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close() 