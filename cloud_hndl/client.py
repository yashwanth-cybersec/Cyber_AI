#!/usr/bin/env python3
"""
Module: Cloud-HNDL Client SDK
File: client.py
Purpose: Client library for Cloud-HNDL Gateway API
"""

import requests
import json
import base64
from typing import Dict, List, Optional, Any, BinaryIO
from dataclasses import dataclass
from datetime import datetime

@dataclass
class TenantInfo:
    tenant_id: str
    name: str
    created_at: str
    status: str
    quota_storage_gb: int
    encryption_policy: str

@dataclass
class UploadResult:
    object_key: str
    size_bytes: int
    encrypted_size_bytes: int
    checksum: str
    time_taken_ms: float

class CloudHNDLClient:
    """Client SDK for Cloud-HNDL Gateway"""
    
    def __init__(self, base_url: str = "http://localhost:8000", api_key: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({
                "Authorization": f"Bearer {api_key}",
                "X-Tenant-ID": "default",
            })
    
    def set_tenant(self, tenant_id: str):
        """Set tenant ID for requests"""
        self.session.headers["X-Tenant-ID"] = tenant_id
    
    # ============================================
    # TENANT MANAGEMENT
    # ============================================
    
    def create_tenant(
        self,
        name: str,
        admin_user_id: str,
        quota_storage_gb: int = 100,
        encryption_policy: str = "hybrid",
    ) -> TenantInfo:
        """Create a new tenant"""
        response = self.session.post(
            f"{self.base_url}/tenants",
            json={
                "name": name,
                "admin_user_id": admin_user_id,
                "quota_storage_gb": quota_storage_gb,
                "quota_requests_per_minute": 1000,
                "encryption_policy": encryption_policy,
                "key_rotation_days": 90,
            }
        )
        response.raise_for_status()
        data = response.json()
        return TenantInfo(**data)
    
    def get_tenant(self, tenant_id: str) -> TenantInfo:
        """Get tenant information"""
        response = self.session.get(f"{self.base_url}/tenants/{tenant_id}")
        response.raise_for_status()
        return TenantInfo(**response.json())
    
    # ============================================
    # FILE OPERATIONS
    # ============================================
    
    def upload_file(
        self,
        file_path: str,
        tenant_id: str = None,
    ) -> UploadResult:
        """Upload and encrypt a file"""
        if tenant_id:
            self.set_tenant(tenant_id)
        
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            data = {'tenant_id': tenant_id or self.session.headers.get("X-Tenant-ID")}
            
            response = self.session.post(
                f"{self.base_url}/upload",
                files=files,
                data=data,
            )
        
        response.raise_for_status()
        data = response.json()
        return UploadResult(
            object_key=data["object_key"],
            size_bytes=data["size_bytes"],
            encrypted_size_bytes=data["encrypted_size_bytes"],
            checksum=data["checksum"],
            time_taken_ms=data["time_taken_ms"],
        )
    
    def upload_bytes(
        self,
        data: bytes,
        filename: str,
        tenant_id: str = None,
    ) -> UploadResult:
        """Upload and encrypt bytes"""
        if tenant_id:
            self.set_tenant(tenant_id)
        
        files = {'file': (filename, data)}
        form_data = {'tenant_id': tenant_id or self.session.headers.get("X-Tenant-ID")}
        
        response = self.session.post(
            f"{self.base_url}/upload",
            files=files,
            data=form_data,
        )
        
        response.raise_for_status()
        resp_data = response.json()
        return UploadResult(
            object_key=resp_data["object_key"],
            size_bytes=resp_data["size_bytes"],
            encrypted_size_bytes=resp_data["encrypted_size_bytes"],
            checksum=resp_data["checksum"],
            time_taken_ms=resp_data["time_taken_ms"],
        )
    
    def download_file(
        self,
        object_key: str,
        output_path: str,
        tenant_id: str = None,
    ) -> None:
        """Download and decrypt a file"""
        if tenant_id:
            self.set_tenant(tenant_id)
        
        t_id = tenant_id or self.session.headers.get("X-Tenant-ID")
        response = self.session.get(
            f"{self.base_url}/download/{t_id}/{object_key}",
            stream=True,
        )
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    
    def download_bytes(
        self,
        object_key: str,
        tenant_id: str = None,
    ) -> bytes:
        """Download and decrypt to bytes"""
        if tenant_id:
            self.set_tenant(tenant_id)
        
        t_id = tenant_id or self.session.headers.get("X-Tenant-ID")
        response = self.session.get(
            f"{self.base_url}/download/{t_id}/{object_key}",
        )
        response.raise_for_status()
        return response.content
    
    # ============================================
    # KEY MANAGEMENT
    # ============================================
    
    def rotate_key(self, key_id: str, tenant_id: str = None, reason: str = "") -> str:
        """Rotate a key"""
        if tenant_id:
            self.set_tenant(tenant_id)
        
        t_id = tenant_id or self.session.headers.get("X-Tenant-ID")
        response = self.session.post(
            f"{self.base_url}/keys/{t_id}/rotate",
            params={"key_id": key_id, "reason": reason},
        )
        response.raise_for_status()
        return response.json()["new_key_id"]
    
    def list_keys(self, tenant_id: str = None) -> List[Dict]:
        """List keys for tenant"""
        if tenant_id:
            self.set_tenant(tenant_id)
        
        t_id = tenant_id or self.session.headers.get("X-Tenant-ID")
        response = self.session.get(f"{self.base_url}/keys/{t_id}")
        response.raise_for_status()
        return response.json().get("keys", [])
    
    # ============================================
    # PRESIGNED URLS
    # ============================================
    
    def get_presigned_upload_url(
        self,
        filename: str,
        tenant_id: str = None,
        expiry_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """Get presigned URL for direct upload"""
        if tenant_id:
            self.set_tenant(tenant_id)
        
        t_id = tenant_id or self.session.headers.get("X-Tenant-ID")
        response = self.session.post(
            f"{self.base_url}/presigned-url",
            params={
                "tenant_id": t_id,
                "filename": filename,
                "expiry_seconds": expiry_seconds,
            },
        )
        response.raise_for_status()
        return response.json()
    
    # ============================================
    # HEALTH & METRICS
    # ============================================
    
    def health_check(self) -> Dict[str, Any]:
        """Check gateway health"""
        response = self.session.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()
    
    def get_metrics(self) -> str:
        """Get Prometheus metrics"""
        response = self.session.get(f"{self.base_url}/metrics")
        response.raise_for_status()
        return response.text

# ============================================
# CLI EXAMPLE
# ============================================

if __name__ == "__main__":
    import os
    import argparse
    
    parser = argparse.ArgumentParser(description="Cloud-HNDL Client CLI")
    parser.add_argument("--url", default="http://localhost:8000", help="Gateway URL")
    parser.add_argument("--tenant", help="Tenant ID")
    parser.add_argument("action", choices=["upload", "download", "health", "create-tenant"])
    parser.add_argument("--file", help="File path")
    parser.add_argument("--output", help="Output path")
    parser.add_argument("--key", help="Object key for download")
    
    args = parser.parse_args()
    
    client = CloudHNDLClient(base_url=args.url)
    
    if args.tenant:
        client.set_tenant(args.tenant)
    
    if args.action == "health":
        result = client.health_check()
        print(json.dumps(result, indent=2))
        
    elif args.action == "create-tenant":
        tenant = client.create_tenant(
            name=args.tenant or "CLI Tenant",
            admin_user_id="cli_admin",
        )
        print(f"Created tenant: {tenant.tenant_id}")
        
    elif args.action == "upload":
        if not args.file:
            print("Error: --file required for upload")
            sys.exit(1)
        result = client.upload_file(args.file)
        print(f"Uploaded: {result.object_key}")
        print(f"Size: {result.size_bytes} -> {result.encrypted_size_bytes} bytes")
        print(f"Time: {result.time_taken_ms:.2f} ms")
        print(f"Checksum: {result.checksum}")
        
    elif args.action == "download":
        if not args.key:
            print("Error: --key required for download")
            sys.exit(1)
        output = args.output or args.key.split('/')[-1]
        client.download_file(args.key, output)
        print(f"Downloaded to: {output}")