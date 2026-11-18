from __future__ import annotations
import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base, scoped_session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./mock_fence.db")

engine = create_engine(DATABASE_URL, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True))
Base = declarative_base()

class Bucket(Base):
    """
    SQLAlchemy model for a storage bucket.

    Attributes:
        id (str): Primary key identifier.
        name (str): Unique bucket name.
        provider (str): Cloud provider type.
        region (str): Cloud region.
        endpoint (str): Endpoint URL.
        auth_mode (str): Authentication mode.
        role_arn (str): Role ARN for cloud provider.
        secret_ref (str): Reference to secret.
        secret_version (str): Version of secret.
        owner_project (str): Owning project.
        labels (str): JSON string of labels.
        status (str): Bucket status.
        created_at (datetime): Creation timestamp.
        updated_at (datetime): Last update timestamp.
    """
    __tablename__ = "bucket"
    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False, index=True)
    provider = Column(String, nullable=False)  # aws|gcp|minio|s3_compatible
    region = Column(String, nullable=True)
    endpoint = Column(String, nullable=True)
    auth_mode = Column(String, nullable=False)  # role|static|workload_identity
    role_arn = Column(String, nullable=True)
    secret_ref = Column(Text, nullable=True)
    secret_version = Column(String, nullable=True)
    owner_project = Column(String, nullable=True)
    labels = Column(Text, nullable=True)  # JSON string for simplicity
    status = Column(String, default="active", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

def init_db() -> None:
    """
    Initialize the database and create all tables.

    Returns:
        None
    """
    Base.metadata.create_all(bind=engine)