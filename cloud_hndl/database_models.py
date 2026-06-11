"""SQLAlchemy database models for Cloud-HNDL"""
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, String, Integer, DateTime, Text, ForeignKey, 
    Boolean, JSON, Index, create_engine
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

Base = declarative_base()

class Tenant(Base):
    __tablename__ = "tenants"
    
    tenant_id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    status = Column(String(32), default="active")
    quota_storage_gb = Column(Integer, default=100)
    quota_requests_per_minute = Column(Integer, default=1000)
    encryption_policy = Column(String(32), default="hybrid")
    key_rotation_days = Column(Integer, default=90)
    master_key_hash = Column(String(128))
    extra_data = Column(JSON)
    
    # Relationships
    keys = relationship("Key", back_populates="tenant", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="tenant")
    access_controls = relationship("AccessControl", back_populates="tenant")

class Key(Base):
    __tablename__ = "keys"
    
    key_id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.tenant_id"), nullable=False)
    key_type = Column(String(32), nullable=False)
    purpose = Column(String(32), nullable=False)
    version = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    status = Column(String(32), default="active")
    public_key = Column(Text, nullable=False)
    private_key_encrypted = Column(Text, nullable=False)
    wrapped_by = Column(String(64), ForeignKey("keys.key_id"), nullable=True)
    algorithm = Column(String(64), nullable=False)
    key_size = Column(Integer, nullable=False)
    extra_data = Column(JSON)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="keys")
    
    __table_args__ = (
        Index("idx_keys_tenant_status", "tenant_id", "status"),
        Index("idx_keys_expires", "expires_at"),
    )

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    log_id = Column(String(64), primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    tenant_id = Column(String(64), ForeignKey("tenants.tenant_id"), nullable=False)
    user_id = Column(String(64), nullable=False)
    action = Column(String(64), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(128), nullable=False)
    details = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="audit_logs")
    
    __table_args__ = (
        Index("idx_audit_tenant_timestamp", "tenant_id", "timestamp"),
        Index("idx_audit_user", "user_id"),
    )

class AccessControl(Base):
    __tablename__ = "access_control"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(64), nullable=False)
    tenant_id = Column(String(64), ForeignKey("tenants.tenant_id"), nullable=False)
    role = Column(String(32), nullable=False)
    permissions = Column(JSON, nullable=False)
    granted_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    # Relationships
    tenant = relationship("Tenant", back_populates="access_controls")
    
    __table_args__ = (
        Index("idx_access_user_tenant", "user_id", "tenant_id", unique=True),
    )

class KeyRotationHistory(Base):
    __tablename__ = "key_rotation_history"
    
    rotation_id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), nullable=False)
    old_key_id = Column(String(64))
    new_key_id = Column(String(64))
    rotated_at = Column(DateTime, default=datetime.utcnow)
    reason = Column(Text)
    
    __table_args__ = (
        Index("idx_rotation_tenant", "tenant_id", "rotated_at"),
    )

def init_database(database_url: str):
    """Initialize database connection and create tables"""
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session
