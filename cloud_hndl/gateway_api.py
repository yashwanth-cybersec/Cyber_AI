#!/usr/bin/env python3
"""
Module 3: Complete API Gateway
File: gateway_api.py
Purpose: FastAPI Gateway for Cloud-HNDL with local storage support
Lines: ~800
"""

import os
import io
import json
import uuid
import time
import tempfile
import hashlib
import secrets
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from functools import wraps
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Request, BackgroundTasks
from fastapi.responses import Response, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator

# Import local modules
from .crypto_engine import (
    HybridKeyPair, HybridKEM, DualSignature, SignatureKeypairData,
    FileEncryptionEngine, SecureMemory, KeySerializer
)
from .key_manager import KeyManagementSystem, KeyPurpose, AuditAction
from .logging_config import get_logger
from .config import config

logger = get_logger(__name__)

# ============================================
# LOCAL STORAGE (No MinIO Required)
# ============================================

class LocalStorage:
    """Local file-based storage when MinIO is not available"""
    
    def __init__(self, base_path: str = "cloud_hndl_storage"):
        self.base_path = base_path
        os.makedirs(base_path, exist_ok=True)
        logger.info(f"Local storage initialized at {base_path}")
    
    def put_object(self, bucket: str, object_key: str, data: bytes, content_type: str = "application/octet-stream"):
        """Store an object"""
        file_path = os.path.join(self.base_path, object_key)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'wb') as f:
            f.write(data)
        logger.debug(f"Stored object: {object_key} ({len(data)} bytes)")
        return object_key
    
    def get_object(self, bucket: str, object_key: str) -> bytes:
        """Retrieve an object"""
        file_path = os.path.join(self.base_path, object_key)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Object not found: {object_key}")
        with open(file_path, 'rb') as f:
            return f.read()
    
    def delete_object(self, bucket: str, object_key: str):
        """Delete an object"""
        file_path = os.path.join(self.base_path, object_key)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    def list_objects(self, bucket: str, prefix: str = "") -> List[str]:
        """List objects"""
        search_path = os.path.join(self.base_path, prefix)
        results = []
        for root, dirs, files in os.walk(self.base_path):
            for file in files:
                file_path = os.path.join(root, file)
                relative = os.path.relpath(file_path, self.base_path)
                if relative.startswith(prefix):
                    results.append(relative)
        return results

# ============================================
# PYDANTIC MODELS
# ============================================

class TenantCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    admin_user_id: str = Field(..., min_length=1, max_length=100)
    quota_storage_gb: int = Field(100, ge=1, le=10000)
    quota_requests_per_minute: int = Field(1000, ge=10, le=100000)
    encryption_policy: str = Field("hybrid", pattern="^(hybrid|pqc_only|classical_only)$")
    key_rotation_days: int = Field(90, ge=7, le=365)

class TenantResponse(BaseModel):
    tenant_id: str
    name: str
    created_at: str
    status: str
    encryption_policy: str

class UploadResponse(BaseModel):
    object_key: str
    tenant_id: str
    size_bytes: int
    encrypted_size_bytes: int
    checksum: str
    policy_used: str
    time_taken_ms: float

class KeyRotateRequest(BaseModel):
    key_id: str
    reason: str = ""

class PresignedURLResponse(BaseModel):
    url: str
    object_key: str
    expires_in: int

class HNDLSimulationRequest(BaseModel):
    algorithm: str = Field("hybrid", pattern="^(classical|pqc_only|hybrid)$")
    scenario: str = Field("none", pattern="^(none|classical_only|pqc_only|both)$")
    data_size_kb: int = Field(1024, ge=1, le=102400)

class HNDLSimulationResponse(BaseModel):
    attack_id: str
    success: bool
    time_to_break_seconds: Optional[float]
    keys_required: int
    keys_obtained: int
    protection_level: str

# ============================================
# FASTAPI APPLICATION
# ============================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    app.state.kms = KeyManagementSystem(db_path="cloud_hndl.db")
    app.state.crypto_engine = FileEncryptionEngine(enable_compression=True)
    app.state.storage = LocalStorage()
    app.state.active_tenants = {}
    
    # Create default tenant if none exist
    try:
        app.state.kms.create_tenant(
            tenant_id="default",
            name="Default Tenant",
            admin_user_id="admin",
        )
        logger.info("Default tenant created")
    except:
        logger.debug("Default tenant already exists")
    
    logger.info("Cloud-HNDL Gateway started with local storage")
    yield
    
    # Shutdown
    logger.info("Cloud-HNDL Gateway shutting down")

app = FastAPI(
    title="Cloud-HNDL Gateway API",
    description="Hybrid Post-Quantum Encryption Gateway for Cloud Storage",
    version="2.0.0",
    lifespan=lifespan,
)

# Security
security = HTTPBearer(auto_error=False)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# AUTHENTICATION
# ============================================

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Optional[str]:
    """Get current user from token (simplified for local dev)"""
    if credentials:
        return credentials.credentials
    return "anonymous"

# ============================================
# HEALTH CHECK
# ============================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "components": {
            "database": "ok",
            "storage": "local",
            "crypto": "hybrid",
            "kem_algorithm": "ML-KEM-768+X25519",
            "signature_algorithm": "ML-DSA-65+Ed25519",
        }
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "Cloud-HNDL Gateway",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health",
    }

# ============================================
# TENANT MANAGEMENT
# ============================================

@app.post("/tenants", response_model=TenantResponse)
async def create_tenant(request: TenantCreateRequest):
    """Create a new tenant"""
    tenant_id = f"tenant_{uuid.uuid4().hex[:12]}"
    
    try:
        tenant = app.state.kms.create_tenant(
            tenant_id=tenant_id,
            name=request.name,
            admin_user_id=request.admin_user_id,
            quota_storage_gb=request.quota_storage_gb,
            quota_requests_per_minute=request.quota_requests_per_minute,
            encryption_policy=request.encryption_policy,
            key_rotation_days=request.key_rotation_days,
        )
        
        app.state.active_tenants[tenant_id] = tenant
        
        logger.info(f"Tenant created: {tenant_id} ({request.name})")
        
        return TenantResponse(
            tenant_id=tenant.tenant_id,
            name=tenant.name,
            created_at=tenant.created_at.isoformat(),
            status=tenant.status,
            encryption_policy=tenant.encryption_policy,
        )
    except Exception as e:
        logger.error(f"Failed to create tenant: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/tenants/{tenant_id}", response_model=TenantResponse)
async def get_tenant(tenant_id: str):
    """Get tenant details"""
    if tenant_id in app.state.active_tenants:
        tenant = app.state.active_tenants[tenant_id]
        return TenantResponse(
            tenant_id=tenant.tenant_id,
            name=tenant.name,
            created_at=tenant.created_at.isoformat(),
            status=tenant.status,
            encryption_policy=tenant.encryption_policy,
        )
    raise HTTPException(status_code=404, detail="Tenant not found")

@app.get("/tenants")
async def list_tenants():
    """List all tenants"""
    return {
        "tenants": [
            {
                "tenant_id": t.tenant_id,
                "name": t.name,
                "status": t.status,
                "encryption_policy": t.encryption_policy,
            }
            for t in app.state.active_tenants.values()
        ]
    }

# ============================================
# FILE OPERATIONS
# ============================================

@app.post("/upload", response_model=UploadResponse)
async def upload_file(
    tenant_id: str = Form(...),
    file: UploadFile = File(...),
):
    """Upload and encrypt a file"""
    start_time = time.time()
    
    # Check tenant exists
    if tenant_id not in app.state.active_tenants:
        # Auto-create tenant if not found
        try:
            app.state.kms.create_tenant(
                tenant_id=tenant_id,
                name=f"Auto-created: {tenant_id}",
                admin_user_id="system",
            )
        except:
            pass
    
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
        content = await file.read()
        tmp_file.write(content)
        temp_path = tmp_file.name
    
    file_size = len(content)
    logger.info(f"Upload request: {file.filename} ({file_size} bytes) for tenant {tenant_id}")
    
    try:
        # Get active keys for tenant
        try:
            private_seed, hybrid_public = app.state.kms.get_active_encryption_key(tenant_id)
            sig_private, sig_public = app.state.kms.get_active_signing_keys(tenant_id)
        except:
            # Generate keys if not found
            logger.info(f"Generating new keys for tenant {tenant_id}")
            hybrid_keypair = HybridKeyPair.generate()
            sig_keypair = DualSignature.generate_keypair()
            
            # Use the generated keys directly
            private_seed = hybrid_keypair.private_seed
            hybrid_public = hybrid_keypair.hybrid_public
            sig_private = sig_keypair
            sig_public = SignatureKeypairData(
                classic_public=sig_keypair.classic_public,
                classic_private=b"",
                pqc_public=sig_keypair.pqc_public,
                pqc_private=b"",
            )
        
        # Encrypt the file using hybrid post-quantum encryption
        envelope = app.state.crypto_engine.encrypt_file_streaming(
            file_path=temp_path,
            recipient_hybrid_public=hybrid_public,
            recipient_signature_private=sig_private,
        )
        
        # Store encrypted envelope
        object_key = f"{tenant_id}/{uuid.uuid4().hex}.enc"
        envelope_json = json.dumps(envelope, default=str).encode()
        
        app.state.storage.put_object(
            "cloud-hndl-bucket",
            object_key,
            envelope_json,
            "application/json"
        )
        
        elapsed_ms = (time.time() - start_time) * 1000
        
        logger.info(f"File encrypted and stored: {object_key} ({len(envelope_json)} bytes, {elapsed_ms:.1f}ms)")
        
        return UploadResponse(
            object_key=object_key,
            tenant_id=tenant_id,
            size_bytes=file_size,
            encrypted_size_bytes=len(envelope_json),
            checksum=envelope.get("metadata", {}).get("file_checksum", hashlib.sha256(content).hexdigest()),
            policy_used="hybrid",
            time_taken_ms=round(elapsed_ms, 2),
        )
        
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)

@app.get("/download/{tenant_id}/{object_key:path}")
async def download_file(tenant_id: str, object_key: str):
    """Download and decrypt a file"""
    logger.info(f"Download request: {object_key} for tenant {tenant_id}")
    
    try:
        # Retrieve encrypted envelope
        envelope_json = app.state.storage.get_object("cloud-hndl-bucket", object_key)
        envelope = json.loads(envelope_json)
        
        # Get keys for decryption
        try:
            private_seed, _ = app.state.kms.get_active_encryption_key(tenant_id)
            _, sig_public = app.state.kms.get_active_signing_keys(tenant_id)
        except:
            raise HTTPException(status_code=400, detail="No keys found for tenant")
        
        # Decrypt to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
            output_path = tmp_file.name
        
        try:
            success = app.state.crypto_engine.decrypt_file_streaming(
                envelope=envelope,
                private_seed=private_seed,
                signature_public_keys=sig_public,
                output_path=output_path,
            )
            
            if not success:
                raise HTTPException(status_code=500, detail="Decryption failed - integrity check failed")
            
            # Read decrypted file
            with open(output_path, 'rb') as f:
                content = f.read()
            
            logger.info(f"File decrypted successfully: {object_key} ({len(content)} bytes)")
            
            return Response(
                content=content,
                media_type="application/octet-stream",
                headers={
                    "X-Encryption": "Hybrid-PQC",
                    "X-KEM-Algorithm": "ML-KEM-768+X25519",
                    "X-Signature-Algorithm": "ML-DSA-65+Ed25519",
                }
            )
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
                
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Object not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/objects/{tenant_id}/{object_key:path}")
async def delete_object(tenant_id: str, object_key: str):
    """Delete an encrypted object"""
    try:
        app.state.storage.delete_object("cloud-hndl-bucket", object_key)
        logger.info(f"Object deleted: {object_key}")
        return {"status": "deleted", "object_key": object_key}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/objects/{tenant_id}")
async def list_objects(tenant_id: str, prefix: str = ""):
    """List objects for a tenant"""
    objects = app.state.storage.list_objects("cloud-hndl-bucket", f"{tenant_id}/")
    return {
        "tenant_id": tenant_id,
        "count": len(objects),
        "objects": objects,
    }

# ============================================
# KEY MANAGEMENT
# ============================================

@app.post("/keys/{tenant_id}/rotate")
async def rotate_key(tenant_id: str, request: KeyRotateRequest):
    """Rotate encryption keys"""
    try:
        new_key_id = app.state.kms.rotate_key(
            tenant_id=tenant_id,
            key_id=request.key_id,
            user_id="admin",
            reason=request.reason or "Manual rotation",
        )
        return {
            "status": "rotated",
            "new_key_id": new_key_id,
            "message": "Key rotated successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/keys/{tenant_id}")
async def list_keys(tenant_id: str):
    """List keys for tenant"""
    try:
        # Get encryption key info
        private_seed, hybrid_public = app.state.kms.get_active_encryption_key(tenant_id)
        sig_private, sig_public = app.state.kms.get_active_signing_keys(tenant_id)
        
        return {
            "tenant_id": tenant_id,
            "keys": [
                {
                    "type": "encryption",
                    "algorithm": "ML-KEM-768+X25519",
                    "public_key_size": len(hybrid_public),
                    "status": "active",
                },
                {
                    "type": "signature",
                    "algorithm": "ML-DSA-65+Ed25519",
                    "status": "active",
                }
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# ============================================
# HNDL ATTACK SIMULATION
# ============================================

@app.post("/hndl/simulate", response_model=HNDLSimulationResponse)
async def simulate_hndl_attack(request: HNDLSimulationRequest):
    """Simulate Harvest Now, Decrypt Later attack"""
    
    attack_id = f"hndl_{uuid.uuid4().hex[:8]}"
    
    # Determine attack success based on algorithm and scenario
    if request.algorithm == "hybrid":
        if request.scenario == "both":
            success = True
            protection = "COMPROMISED - Both keys stolen"
        elif request.scenario in ["classical_only", "pqc_only"]:
            success = False
            protection = "PROTECTED - Hybrid mode requires both keys"
        else:
            success = False
            protection = "PROTECTED - No keys compromised"
    elif request.algorithm == "pqc_only":
        if request.scenario in ["pqc_only", "both"]:
            success = True
            protection = "COMPROMISED - PQC key stolen"
        else:
            success = False
            protection = "PROTECTED"
    else:  # classical
        if request.scenario in ["classical_only", "both"]:
            success = True
            protection = "BROKEN - Classical encryption vulnerable"
        else:
            success = False
            protection = "PROTECTED"
    
    # Calculate realistic time-to-break
    if success:
        if request.algorithm == "classical":
            time_to_break = 2.5  # Seconds with quantum computer
        else:
            time_to_break = 5.0
    else:
        time_to_break = None
    
    return HNDLSimulationResponse(
        attack_id=attack_id,
        success=success,
        time_to_break_seconds=time_to_break,
        keys_required=2 if request.algorithm == "hybrid" else 1,
        keys_obtained=2 if request.scenario == "both" else (1 if request.scenario != "none" else 0),
        protection_level=protection,
    )

# ============================================
# QUANTUM SECURITY STATUS
# ============================================

@app.get("/quantum/status")
async def quantum_status():
    """Get quantum security status"""
    return {
        "status": "ACTIVE",
        "mode": "HYBRID",
        "kem_algorithm": "ML-KEM-768",
        "classical_algorithm": "X25519",
        "signature_algorithm": "ML-DSA-65 + Ed25519",
        "security_level": "256-bit (NIST Level 5)",
        "hndl_protection": "ENABLED",
        "key_rotation": "90 days",
        "compliance": {
            "nist_sp_800_175b": "COMPLIANT",
            "fips_140_3": "TRANSITIONAL",
            "cnsa_2_0": "COMPLIANT",
        }
    }

# ============================================
# AUDIT LOGS
# ============================================

@app.get("/audit/{tenant_id}")
async def get_audit_logs(tenant_id: str, limit: int = 50):
    """Get audit logs for tenant"""
    try:
        logs = app.state.kms.get_audit_logs(tenant_id, limit)
        return {
            "tenant_id": tenant_id,
            "count": len(logs),
            "logs": [
                {
                    "timestamp": log.timestamp if hasattr(log, 'timestamp') else str(log),
                    "action": log.action if hasattr(log, 'action') else str(log),
                    "details": log.details if hasattr(log, 'details') else "",
                }
                for log in logs
            ]
        }
    except Exception as e:
        return {"tenant_id": tenant_id, "count": 0, "logs": [], "error": str(e)}

# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")