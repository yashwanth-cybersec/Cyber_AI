#!/usr/bin/env python3
"""
Module 2: Complete Key Management System
File: key_manager.py
Purpose: Full key lifecycle management with database backend
Lines: ~900
"""

import os
import json
import base64
import uuid
import hashlib
import secrets
import threading
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime, timedelta
from contextlib import contextmanager
import sqlite3

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto_engine import (
    HybridKeyPair, HybridKeyPairData, DualSignature, SignatureKeypairData,
    KeySerializer, SecureMemory
)
from .logging_config import get_logger

logger = get_logger(__name__)


# ============================================
# ENUMS AND DATA CLASSES
# ============================================

class KeyStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"
    DEPRECATED = "deprecated"

class KeyPurpose(Enum):
    ENCRYPTION = "encryption"
    SIGNING = "signing"
    AUTHENTICATION = "authentication"

class AuditAction(Enum):
    KEY_GENERATED = "key_generated"
    KEY_ROTATED = "key_rotated"
    KEY_REVOKED = "key_revoked"
    KEY_EXPORTED = "key_exported"
    KEY_BACKUP = "key_backup"
    KEY_RESTORE = "key_restore"
    ACCESS_GRANTED = "access_granted"
    ACCESS_REVOKED = "access_revoked"
    TENANT_CREATED = "tenant_created"
    TENANT_DELETED = "tenant_deleted"
    ENCRYPTION_PERFORMED = "encryption_performed"
    DECRYPTION_PERFORMED = "decryption_performed"

@dataclass
class Tenant:
    tenant_id: str
    name: str
    created_at: datetime
    status: str
    quota_storage_gb: int
    quota_requests_per_minute: int
    encryption_policy: str
    key_rotation_days: int
    master_key_hash: str = ""

@dataclass
class KeyRecord:
    key_id: str
    tenant_id: str
    key_type: str
    purpose: str
    version: int
    created_at: datetime
    expires_at: datetime
    status: str
    public_key: str
    private_key_encrypted: str
    wrapped_by: Optional[str] = None
    algorithm: str = "ML-KEM-768+X25519"
    key_size: int = 256

@dataclass
class AuditLog:
    log_id: str
    timestamp: str
    tenant_id: str
    user_id: str
    action: str
    resource_type: str
    resource_id: str
    details: str = ""
    ip_address: str = ""
    user_agent: str = ""

@dataclass
class AccessControl:
    user_id: str
    tenant_id: str
    role: str
    permissions: List[str]
    granted_at: str
    expires_at: Optional[str] = None


# ============================================
# DATABASE MANAGER
# ============================================

class DatabaseManager:
    """SQLite database manager for key storage"""
    
    def __init__(self, db_path: str = "cloud_hndl.db"):
        self.db_path = db_path
        self._init_schema()
        logger.info(f"Database initialized at {db_path}")
    
    def _init_schema(self):
        """Initialize database schema"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    tenant_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    quota_storage_gb INTEGER DEFAULT 100,
                    quota_requests_per_minute INTEGER DEFAULT 1000,
                    encryption_policy TEXT DEFAULT 'hybrid',
                    key_rotation_days INTEGER DEFAULT 90,
                    master_key_hash TEXT DEFAULT ''
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS keys (
                    key_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    key_type TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key_encrypted TEXT NOT NULL,
                    wrapped_by TEXT,
                    algorithm TEXT NOT NULL,
                    key_size INTEGER NOT NULL,
                    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    log_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    details TEXT DEFAULT '',
                    ip_address TEXT DEFAULT '',
                    user_agent TEXT DEFAULT ''
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS access_control (
                    user_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    granted_at TEXT NOT NULL,
                    expires_at TEXT,
                    PRIMARY KEY (user_id, tenant_id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS key_rotation_history (
                    rotation_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    old_key_id TEXT,
                    new_key_id TEXT,
                    rotated_at TEXT NOT NULL,
                    reason TEXT DEFAULT ''
                )
            """)
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Get database connection with context manager"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()


# ============================================
# KEY MANAGEMENT SYSTEM
# ============================================

class KeyManagementSystem:
    """
    Complete Key Management System with:
    - SQLite database backend
    - Key generation and storage
    - Key rotation with versioning
    - Key backup and restore
    - Access control (RBAC)
    - Audit logging
    """
    
    def __init__(self, db_path: str = "cloud_hndl.db", master_password: str = None):
        self.db = DatabaseManager(db_path)
        self.master_key = self._init_master_key(master_password)
        self.audit_queue = []
        self.audit_thread = threading.Thread(target=self._process_audit_queue, daemon=True)
        self.audit_thread.start()
        logger.info("Key Management System initialized")
    
    def _init_master_key(self, master_password: str = None) -> bytes:
        """Initialize or load master encryption key"""
        if master_password:
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = kdf.derive(master_password.encode())
            return base64.urlsafe_b64encode(key)[:32]
        else:
            # Development mode - use a generated key
            return secrets.token_bytes(32)
    
    def _encrypt_private_key(self, private_key: bytes) -> str:
        """Encrypt private key with master key"""
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self.master_key)
        ciphertext = aesgcm.encrypt(nonce, private_key, None)
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode()
    
    def _decrypt_private_key(self, encrypted: str) -> bytes:
        """Decrypt private key with master key"""
        data = base64.b64decode(encrypted)
        nonce = data[:12]
        ciphertext = data[12:]
        aesgcm = AESGCM(self.master_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _log_audit(self, tenant_id: str, user_id: str, action: AuditAction,
                   resource_type: str, resource_id: str, details: str = "",
                   ip_address: str = "", user_agent: str = ""):
        """Add audit log entry to queue"""
        log = AuditLog(
            log_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow().isoformat(),
            tenant_id=tenant_id,
            user_id=user_id,
            action=action.value,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.audit_queue.append(log)
    
    def _process_audit_queue(self):
        """Process audit logs in background thread"""
        while True:
            time.sleep(1)
            if self.audit_queue:
                batch = self.audit_queue[:50]
                self.audit_queue = self.audit_queue[50:]
                try:
                    with self.db.get_connection() as conn:
                        cursor = conn.cursor()
                        for log in batch:
                            cursor.execute("""
                                INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                log.log_id, log.timestamp, log.tenant_id, log.user_id,
                                log.action, log.resource_type, log.resource_id,
                                log.details, log.ip_address, log.user_agent
                            ))
                        conn.commit()
                except Exception as e:
                    logger.error(f"Failed to write audit logs: {e}")
    
    # ============================================
    # TENANT MANAGEMENT
    # ============================================
    
    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        admin_user_id: str,
        quota_storage_gb: int = 100,
        quota_requests_per_minute: int = 1000,
        encryption_policy: str = "hybrid",
        key_rotation_days: int = 90,
    ) -> Tenant:
        """Create a new tenant with initial encryption keys"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if tenant already exists
            cursor.execute("SELECT tenant_id FROM tenants WHERE tenant_id = ?", (tenant_id,))
            if cursor.fetchone():
                raise Exception(f"Tenant '{tenant_id}' already exists")
            
            tenant = Tenant(
                tenant_id=tenant_id,
                name=name,
                created_at=datetime.utcnow(),
                status="active",
                quota_storage_gb=quota_storage_gb,
                quota_requests_per_minute=quota_requests_per_minute,
                encryption_policy=encryption_policy,
                key_rotation_days=key_rotation_days,
            )
            
            cursor.execute("""
                INSERT INTO tenants VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tenant.tenant_id, tenant.name, tenant.created_at.isoformat(),
                tenant.status, tenant.quota_storage_gb,
                tenant.quota_requests_per_minute, tenant.encryption_policy,
                tenant.key_rotation_days, tenant.master_key_hash
            ))
            
            conn.commit()
        
        # Generate initial keys
        self._generate_initial_keys(tenant_id, admin_user_id)
        
        self._log_audit(tenant_id, admin_user_id, AuditAction.TENANT_CREATED,
                       "tenant", tenant_id, f"Created tenant '{name}'")
        
        logger.info(f"Tenant created: {tenant_id} ({name})")
        return tenant
    
    def _generate_initial_keys(self, tenant_id: str, user_id: str):
        """Generate initial encryption and signing keys for a tenant"""
        encryption_key_id = f"enc_{tenant_id}_v1"
        signing_key_id = f"sig_{tenant_id}_v1"
        
        # Generate hybrid encryption keypair
        hybrid_keypair = HybridKeyPair.generate()
        encrypted_enc_private = self._encrypt_private_key(hybrid_keypair.private_seed)
        
        # Generate signature keypair
        sig_keypair = DualSignature.generate_keypair()
        combined_sig_private = sig_keypair.classic_private + sig_keypair.pqc_private
        encrypted_sig_private = self._encrypt_private_key(combined_sig_private)
        combined_sig_public = sig_keypair.classic_public + sig_keypair.pqc_public
        
        now = datetime.utcnow()
        expires = now + timedelta(days=90)
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Store encryption key
            cursor.execute("""
                INSERT INTO keys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                encryption_key_id, tenant_id, "hybrid", KeyPurpose.ENCRYPTION.value,
                1, now.isoformat(), expires.isoformat(), KeyStatus.ACTIVE.value,
                base64.b64encode(hybrid_keypair.hybrid_public).decode(),
                encrypted_enc_private, None, "ML-KEM-768+X25519", 256
            ))
            
            # Store signing key
            cursor.execute("""
                INSERT INTO keys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                signing_key_id, tenant_id, "signature", KeyPurpose.SIGNING.value,
                1, now.isoformat(), expires.isoformat(), KeyStatus.ACTIVE.value,
                base64.b64encode(combined_sig_public).decode(),
                encrypted_sig_private, None, "ML-DSA-65+Ed25519", 256
            ))
            
            conn.commit()
        
        self._log_audit(tenant_id, user_id, AuditAction.KEY_GENERATED,
                       "key", encryption_key_id, "Initial encryption key generated")
        self._log_audit(tenant_id, user_id, AuditAction.KEY_GENERATED,
                       "key", signing_key_id, "Initial signing key generated")
        
        logger.info(f"Initial keys generated for tenant {tenant_id}")
    
    # ============================================
    # KEY ACCESS
    # ============================================
    
    def get_active_encryption_key(self, tenant_id: str) -> Tuple[bytes, bytes]:
        """Get the active encryption key for a tenant (returns private_seed, hybrid_public)"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM keys
                WHERE tenant_id = ? AND key_type = 'hybrid' AND status = 'active'
                ORDER BY version DESC LIMIT 1
            """, (tenant_id,))
            
            row = cursor.fetchone()
            if not row:
                # Auto-generate keys if none exist
                logger.info(f"No keys found for tenant {tenant_id}, generating...")
                self._generate_initial_keys(tenant_id, "system")
                
                # Try again
                cursor.execute("""
                    SELECT * FROM keys
                    WHERE tenant_id = ? AND key_type = 'hybrid' AND status = 'active'
                    ORDER BY version DESC LIMIT 1
                """, (tenant_id,))
                row = cursor.fetchone()
            
            if not row:
                raise Exception(f"No encryption keys for tenant {tenant_id}")
            
            private_seed = self._decrypt_private_key(row["private_key_encrypted"])
            hybrid_public = base64.b64decode(row["public_key"])
            
            return private_seed, hybrid_public
    
    def get_active_signing_keys(self, tenant_id: str) -> Tuple[SignatureKeypairData, SignatureKeypairData]:
        """Get active signing keypair (private and public)"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM keys
                WHERE tenant_id = ? AND key_type = 'signature' AND status = 'active'
                ORDER BY version DESC LIMIT 1
            """, (tenant_id,))
            
            row = cursor.fetchone()
            if not row:
                # Auto-generate if none exist
                logger.info(f"No signing keys for tenant {tenant_id}, generating...")
                self._generate_initial_keys(tenant_id, "system")
                
                cursor.execute("""
                    SELECT * FROM keys
                    WHERE tenant_id = ? AND key_type = 'signature' AND status = 'active'
                    ORDER BY version DESC LIMIT 1
                """, (tenant_id,))
                row = cursor.fetchone()
            
            if not row:
                raise Exception(f"No signing keys for tenant {tenant_id}")
            
            combined_private = self._decrypt_private_key(row["private_key_encrypted"])
            combined_public = base64.b64decode(row["public_key"])
            
            # Split combined keys
            classic_private = combined_private[:64]
            pqc_private = combined_private[64:]
            classic_public = combined_public[:32]
            pqc_public = combined_public[32:]
            
            private_keys = SignatureKeypairData(
                classic_public=classic_public,
                classic_private=classic_private,
                pqc_public=pqc_public,
                pqc_private=pqc_private,
            )
            
            public_keys = SignatureKeypairData(
                classic_public=classic_public,
                classic_private=b"",
                pqc_public=pqc_public,
                pqc_private=b"",
            )
            
            return private_keys, public_keys
    
    # ============================================
    # KEY ROTATION
    # ============================================
    
    def rotate_key(self, tenant_id: str, key_id: str, user_id: str, reason: str = "") -> str:
        """Rotate a key - deprecate old, create new version"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM keys WHERE key_id = ? AND tenant_id = ?",
                          (key_id, tenant_id))
            old_key = cursor.fetchone()
            
            if not old_key:
                raise Exception(f"Key '{key_id}' not found")
            
            # Deprecate old key
            cursor.execute("UPDATE keys SET status = ? WHERE key_id = ?",
                          (KeyStatus.DEPRECATED.value, key_id))
            
            # Generate new key
            version = old_key["version"] + 1
            base_name = key_id.rsplit("_v", 1)[0]
            new_key_id = f"{base_name}_v{version}"
            
            now = datetime.utcnow()
            expires = now + timedelta(days=90)
            
            if old_key["key_type"] == "hybrid":
                keypair = HybridKeyPair.generate()
                encrypted_private = self._encrypt_private_key(keypair.private_seed)
                public_key_b64 = base64.b64encode(keypair.hybrid_public).decode()
                algorithm = "ML-KEM-768+X25519"
            else:
                sig_keypair = DualSignature.generate_keypair()
                combined_private = sig_keypair.classic_private + sig_keypair.pqc_private
                combined_public = sig_keypair.classic_public + sig_keypair.pqc_public
                encrypted_private = self._encrypt_private_key(combined_private)
                public_key_b64 = base64.b64encode(combined_public).decode()
                algorithm = "ML-DSA-65+Ed25519"
            
            cursor.execute("""
                INSERT INTO keys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                new_key_id, tenant_id, old_key["key_type"], old_key["purpose"],
                version, now.isoformat(), expires.isoformat(), KeyStatus.ACTIVE.value,
                public_key_b64, encrypted_private, key_id, algorithm, old_key["key_size"]
            ))
            
            # Record rotation
            rotation_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO key_rotation_history VALUES (?, ?, ?, ?, ?, ?)
            """, (rotation_id, tenant_id, key_id, new_key_id, now.isoformat(), reason))
            
            conn.commit()
        
        self._log_audit(tenant_id, user_id, AuditAction.KEY_ROTATED,
                       "key", key_id, f"Rotated to {new_key_id}: {reason}")
        
        logger.info(f"Key rotated: {key_id} -> {new_key_id}")
        return new_key_id
    
    # ============================================
    # KEY BACKUP AND RESTORE
    # ============================================
    
    def backup_keys(self, tenant_id: str, user_id: str) -> Dict[str, Any]:
        """Create encrypted backup of all tenant keys"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM keys WHERE tenant_id = ?", (tenant_id,))
            keys = cursor.fetchall()
        
        backup_data = {
            "tenant_id": tenant_id,
            "timestamp": datetime.utcnow().isoformat(),
            "keys": []
        }
        
        for key in keys:
            backup_data["keys"].append({
                "key_id": key["key_id"],
                "key_type": key["key_type"],
                "purpose": key["purpose"],
                "version": key["version"],
                "created_at": key["created_at"],
                "expires_at": key["expires_at"],
                "status": key["status"],
                "public_key": key["public_key"],
                "private_key_encrypted": key["private_key_encrypted"],
                "algorithm": key["algorithm"],
            })
        
        backup_json = json.dumps(backup_data).encode()
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self.master_key)
        encrypted_backup = aesgcm.encrypt(nonce, backup_json, None)
        
        backup_file = f"backup_{tenant_id}_{int(datetime.utcnow().timestamp())}.bin"
        with open(backup_file, 'wb') as f:
            f.write(nonce)
            f.write(encrypted_backup)
        
        self._log_audit(tenant_id, user_id, AuditAction.KEY_BACKUP,
                       "backup", backup_file, f"Backed up {len(keys)} keys")
        
        logger.info(f"Keys backed up: {backup_file} ({len(keys)} keys)")
        return {"backup_file": backup_file, "key_count": len(keys)}
    
    def restore_keys(self, tenant_id: str, backup_file: str, user_id: str) -> int:
        """Restore keys from encrypted backup"""
        with open(backup_file, 'rb') as f:
            nonce = f.read(12)
            encrypted_backup = f.read()
        
        aesgcm = AESGCM(self.master_key)
        backup_json = aesgcm.decrypt(nonce, encrypted_backup, None)
        backup_data = json.loads(backup_json)
        
        if backup_data["tenant_id"] != tenant_id:
            raise Exception("Backup tenant ID mismatch")
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM keys WHERE tenant_id = ?", (tenant_id,))
            
            count = 0
            for key in backup_data["keys"]:
                cursor.execute("""
                    INSERT INTO keys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    key["key_id"], tenant_id, key["key_type"], key["purpose"],
                    key["version"], key["created_at"], key["expires_at"],
                    key["status"], key["public_key"], key["private_key_encrypted"],
                    None, key["algorithm"], 256
                ))
                count += 1
            
            conn.commit()
        
        self._log_audit(tenant_id, user_id, AuditAction.KEY_RESTORE,
                       "backup", backup_file, f"Restored {count} keys")
        
        logger.info(f"Keys restored: {count} keys from {backup_file}")
        return count
    
    # ============================================
    # ACCESS CONTROL
    # ============================================
    
    def grant_access(self, user_id: str, tenant_id: str, role: str,
                     permissions: List[str], expires_days: int = None) -> AccessControl:
        """Grant user access to a tenant"""
        now = datetime.utcnow()
        expires_at = None
        
        if expires_days:
            expires_at = (now + timedelta(days=expires_days)).isoformat()
        
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO access_control VALUES (?, ?, ?, ?, ?, ?)
            """, (
                user_id, tenant_id, role, json.dumps(permissions),
                now.isoformat(), expires_at
            ))
            conn.commit()
        
        self._log_audit(tenant_id, user_id, AuditAction.ACCESS_GRANTED,
                       "access", f"{user_id}:{tenant_id}", f"Role: {role}")
        
        return AccessControl(
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
            permissions=permissions,
            granted_at=now.isoformat(),
            expires_at=expires_at,
        )
    
    def check_access(self, user_id: str, tenant_id: str, required_permission: str) -> bool:
        """Check if a user has a specific permission"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM access_control WHERE user_id = ? AND tenant_id = ?
            """, (user_id, tenant_id))
            
            row = cursor.fetchone()
            if not row:
                return False
            
            if row["expires_at"]:
                try:
                    expires = datetime.fromisoformat(row["expires_at"])
                    if datetime.utcnow() > expires:
                        return False
                except:
                    pass
            
            permissions = json.loads(row["permissions"])
            return "*" in permissions or required_permission in permissions
    
    # ============================================
    # AUDIT LOGS
    # ============================================
    
    def get_audit_logs(self, tenant_id: str, limit: int = 100) -> List[AuditLog]:
        """Get audit logs for a tenant"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM audit_logs
                WHERE tenant_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (tenant_id, limit))
            
            logs = []
            for row in cursor.fetchall():
                logs.append(AuditLog(
                    log_id=row["log_id"],
                    timestamp=row["timestamp"],
                    tenant_id=row["tenant_id"],
                    user_id=row["user_id"],
                    action=row["action"],
                    resource_type=row["resource_type"],
                    resource_id=row["resource_id"],
                    details=row["details"],
                    ip_address=row["ip_address"],
                    user_agent=row["user_agent"],
                ))
            
            return logs
    
    # ============================================
    # CLEANUP
    # ============================================
    
    def cleanup_expired_keys(self) -> int:
        """Mark expired keys as EXPIRED"""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.utcnow().isoformat()
            cursor.execute("""
                UPDATE keys SET status = ?
                WHERE expires_at < ? AND status = 'active'
            """, (KeyStatus.EXPIRED.value, now))
            count = cursor.rowcount
            conn.commit()
        
        if count > 0:
            logger.info(f"Cleaned up {count} expired keys")
        
        return count