#!/usr/bin/env python3
"""
Module: Cloud KMS Integration
File: cloud_kms.py
Purpose: Integration with cloud KMS providers (AWS KMS, Azure Key Vault, GCP KMS)
Supports: Bring Your Own Key (BYOK), envelope encryption, key rotation
Lines: 584+
"""

import os
import json
import base64
import hashlib
import secrets
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ============================================
# AWS IMPORTS WITH PROPER FALLBACK
# ============================================

try:
    import boto3
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False
    boto3 = None

# ============================================
# AZURE IMPORTS WITH PROPER FALLBACK
# ============================================

try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    DefaultAzureCredential = None
    KeyClient = None
    CryptographyClient = None
    
    # Create fallback class with all required attributes so code doesn't crash
    class EncryptionAlgorithm:
        """Fallback EncryptionAlgorithm when Azure SDK is not installed"""
        rsa_oaep_256 = "rsa_oaep_256"
        rsa_oaep = "rsa_oaep"
        rsa1_5 = "rsa1_5"
        aes_gcm_256 = "aes_gcm_256"
        aes_cbc_256 = "aes_cbc_256"
        @classmethod
        def _missing_(cls, value):
            return cls.rsa_oaep_256

# ============================================
# GCP IMPORTS WITH PROPER FALLBACK
# ============================================

try:
    import google.cloud.kms
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    google = None

from .crypto_engine import HybridKeyPair, SecureMemory
from .logging_config import get_logger

logger = get_logger(__name__)

# ============================================
# CLOUD KMS PROVIDER TYPES
# ============================================

class KMSProvider(Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    LOCAL = "local"

@dataclass
class KMSKeyMetadata:
    """Metadata for a KMS-managed key"""
    key_id: str
    provider: KMSProvider
    region: Optional[str] = None
    key_spec: str = ""
    purpose: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    rotation_enabled: bool = False
    rotation_period_days: Optional[int] = None
    aliases: list = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)

# ============================================
# AWS KMS INTEGRATION
# ============================================

class AWSKMSClient:
    """AWS KMS integration with envelope encryption"""
    
    def __init__(self, region: str = "us-east-1", profile: str = None):
        if not AWS_AVAILABLE:
            raise ImportError("boto3 is required for AWS KMS. Install with: pip install boto3")
        
        self.region = region
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        self.client = session.client('kms', region_name=region)
        logger.info(f"AWS KMS client initialized in {region}")
        
    def create_key(
        self,
        alias: str,
        description: str = "Cloud-HNDL encryption key",
        key_spec: str = "SYMMETRIC_DEFAULT",
        rotation_enabled: bool = True,
        tags: Dict[str, str] = None,
    ) -> KMSKeyMetadata:
        """Create a new KMS key"""
        if not AWS_AVAILABLE:
            raise ImportError("AWS KMS requires boto3")
            
        response = self.client.create_key(
            Description=description,
            KeySpec=key_spec,
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS',
            Tags=[{'TagKey': k, 'TagValue': v} for k, v in (tags or {}).items()],
        )
        
        key_id = response['KeyMetadata']['KeyId']
        
        # Create alias
        self.client.create_alias(
            AliasName=f'alias/{alias}',
            TargetKeyId=key_id,
        )
        
        # Enable rotation
        if rotation_enabled and key_spec == "SYMMETRIC_DEFAULT":
            self.client.enable_key_rotation(KeyId=key_id)
        
        logger.info(f"Created AWS KMS key: {key_id} (alias: {alias})")
        
        return KMSKeyMetadata(
            key_id=key_id,
            provider=KMSProvider.AWS,
            region=self.region,
            key_spec=key_spec,
            purpose='ENCRYPT_DECRYPT',
            created_at=response['KeyMetadata']['CreationDate'],
            rotation_enabled=rotation_enabled,
            aliases=[alias],
            tags=tags or {},
        )
    
    def encrypt(
        self,
        key_id: str,
        plaintext: bytes,
        encryption_context: Dict[str, str] = None,
    ) -> Tuple[bytes, bytes]:
        """Encrypt data using envelope encryption"""
        # Generate data key
        response = self.client.generate_data_key(
            KeyId=key_id,
            KeySpec='AES_256',
            EncryptionContext=encryption_context or {},
        )
        
        data_key_plain = response['Plaintext']
        data_key_encrypted = response['CiphertextBlob']
        
        # Encrypt with AES-GCM
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(data_key_plain)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Securely wipe plaintext data key
        SecureMemory.wipe(bytearray(data_key_plain))
        
        # Format: encrypted_key (variable) + nonce (12) + ciphertext
        encrypted_key_len = len(data_key_encrypted).to_bytes(2, 'big')
        result = encrypted_key_len + data_key_encrypted + nonce + ciphertext
        
        return result, data_key_encrypted
    
    def decrypt(
        self,
        ciphertext: bytes,
        encryption_context: Dict[str, str] = None,
    ) -> bytes:
        """Decrypt data using envelope encryption"""
        # Parse components
        key_len = int.from_bytes(ciphertext[:2], 'big')
        encrypted_key = ciphertext[2:2+key_len]
        nonce = ciphertext[2+key_len:14+key_len]
        encrypted_data = ciphertext[14+key_len:]
        
        # Decrypt data key
        response = self.client.decrypt(
            CiphertextBlob=encrypted_key,
            EncryptionContext=encryption_context or {},
        )
        data_key = response['Plaintext']
        
        # Decrypt data
        aesgcm = AESGCM(data_key)
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
        
        # Securely wipe data key
        SecureMemory.wipe(bytearray(data_key))
        
        return plaintext
    
    def re_encrypt(
        self,
        ciphertext: bytes,
        source_key_id: str,
        destination_key_id: str,
        encryption_context: Dict[str, str] = None,
    ) -> bytes:
        """Re-encrypt data with a different key"""
        # Decrypt data key
        key_len = int.from_bytes(ciphertext[:2], 'big')
        encrypted_key = ciphertext[2:2+key_len]
        
        response = self.client.re_encrypt(
            CiphertextBlob=encrypted_key,
            SourceKeyId=source_key_id,
            DestinationKeyId=destination_key_id,
            SourceEncryptionContext=encryption_context or {},
            DestinationEncryptionContext=encryption_context or {},
        )
        
        new_encrypted_key = response['CiphertextBlob']
        
        # Rebuild ciphertext with new encrypted key
        new_key_len = len(new_encrypted_key).to_bytes(2, 'big')
        result = new_key_len + new_encrypted_key + ciphertext[2+key_len:]
        
        return result
    
    def sign(
        self,
        key_id: str,
        message: bytes,
        signing_algorithm: str = "RSASSA_PKCS1_V1_5_SHA_256",
    ) -> bytes:
        """Sign message using KMS key"""
        response = self.client.sign(
            KeyId=key_id,
            Message=message,
            MessageType='RAW',
            SigningAlgorithm=signing_algorithm,
        )
        return response['Signature']
    
    def verify(
        self,
        key_id: str,
        message: bytes,
        signature: bytes,
        signing_algorithm: str = "RSASSA_PKCS1_V1_5_SHA_256",
    ) -> bool:
        """Verify signature using KMS key"""
        response = self.client.verify(
            KeyId=key_id,
            Message=message,
            MessageType='RAW',
            Signature=signature,
            SigningAlgorithm=signing_algorithm,
        )
        return response['SignatureValid']

# ============================================
# AZURE KEY VAULT INTEGRATION
# ============================================

class AzureKeyVaultClient:
    """Azure Key Vault integration"""
    
    def __init__(self, vault_url: str):
        if not AZURE_AVAILABLE:
            raise ImportError("Azure SDK is required. Install with: pip install azure-identity azure-keyvault-keys")
        
        self.vault_url = vault_url
        credential = DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=vault_url, credential=credential)
        logger.info(f"Azure Key Vault client initialized: {vault_url}")
        
    def create_key(
        self,
        name: str,
        key_type: str = "RSA-HSM",
        size: int = 3072,
        rotation_policy: Dict = None,
        tags: Dict[str, str] = None,
    ) -> KMSKeyMetadata:
        """Create a new key in Azure Key Vault"""
        key = self.key_client.create_key(
            name=name,
            key_type=key_type,
            size=size,
            tags=tags,
        )
        
        logger.info(f"Created Azure Key Vault key: {name}")
        
        return KMSKeyMetadata(
            key_id=key.id,
            provider=KMSProvider.AZURE,
            region=None,
            key_spec=f"{key_type}-{size}",
            purpose='ENCRYPT_DECRYPT',
            created_at=datetime.fromtimestamp(key.properties.created_on) if hasattr(key.properties, 'created_on') else datetime.utcnow(),
            rotation_enabled=rotation_policy is not None,
            rotation_period_days=rotation_policy.get('lifetime_actions', [{}])[0].get('trigger', {}).get('time_after_create') if rotation_policy else None,
            aliases=[name],
            tags=tags or {},
        )
    
    def encrypt(
        self,
        key_name: str,
        plaintext: bytes,
        algorithm = None,
    ) -> bytes:
        """Encrypt data using Azure Key Vault key"""
        if algorithm is None:
            algorithm = EncryptionAlgorithm.rsa_oaep_256
        
        crypto_client = CryptographyClient(
            key_id=f"{self.vault_url}/keys/{key_name}",
            credential=DefaultAzureCredential(),
        )
        
        result = crypto_client.encrypt(algorithm, plaintext)
        return result.ciphertext
    
    def decrypt(
        self,
        key_name: str,
        ciphertext: bytes,
        algorithm = None,
    ) -> bytes:
        """Decrypt data using Azure Key Vault key"""
        if algorithm is None:
            algorithm = EncryptionAlgorithm.rsa_oaep_256
        
        crypto_client = CryptographyClient(
            key_id=f"{self.vault_url}/keys/{key_name}",
            credential=DefaultAzureCredential(),
        )
        
        result = crypto_client.decrypt(algorithm, ciphertext)
        return result.plaintext
    
    def sign(
        self,
        key_name: str,
        digest: bytes,
        algorithm: str = "ES256",
    ) -> bytes:
        """Sign digest using Azure Key Vault key"""
        crypto_client = CryptographyClient(
            key_id=f"{self.vault_url}/keys/{key_name}",
            credential=DefaultAzureCredential(),
        )
        
        result = crypto_client.sign(algorithm, digest)
        return result.signature
    
    def verify(
        self,
        key_name: str,
        digest: bytes,
        signature: bytes,
        algorithm: str = "ES256",
    ) -> bool:
        """Verify signature using Azure Key Vault key"""
        crypto_client = CryptographyClient(
            key_id=f"{self.vault_url}/keys/{key_name}",
            credential=DefaultAzureCredential(),
        )
        
        result = crypto_client.verify(algorithm, digest, signature)
        return result.is_valid

# ============================================
# GCP KMS INTEGRATION
# ============================================

class GCPKMSClient:
    """Google Cloud KMS integration"""
    
    def __init__(self, project_id: str, location_id: str = "global"):
        if not GCP_AVAILABLE:
            raise ImportError("Google Cloud KMS is required. Install with: pip install google-cloud-kms")
        
        self.project_id = project_id
        self.location_id = location_id
        self.client = google.cloud.kms.KeyManagementServiceClient()
        logger.info(f"GCP KMS client initialized: {project_id}/{location_id}")
        
    def create_key_ring(self, key_ring_id: str) -> str:
        """Create a key ring"""
        location_name = self.client.common_location_path(self.project_id, self.location_id)
        
        key_ring = self.client.create_key_ring(
            request={
                "parent": location_name,
                "key_ring_id": key_ring_id,
            }
        )
        
        logger.info(f"Created key ring: {key_ring_id}")
        return key_ring.name
    
    def create_key(
        self,
        key_ring_id: str,
        key_id: str,
        purpose: str = "ENCRYPT_DECRYPT",
        rotation_period: str = "7776000s",  # 90 days
    ) -> KMSKeyMetadata:
        """Create a new crypto key"""
        key_ring_name = self.client.key_ring_path(self.project_id, self.location_id, key_ring_id)
        
        crypto_key = {
            "purpose": google.cloud.kms.CryptoKey.CryptoKeyPurpose[purpose],
            "version_template": {
                "algorithm": google.cloud.kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION,
                "protection_level": google.cloud.kms.ProtectionLevel.HSM,
            },
        }
        
        if rotation_period:
            crypto_key["rotation_period"] = rotation_period
            crypto_key["next_rotation_time"] = {
                "seconds": int((datetime.utcnow() + timedelta(days=90)).timestamp())
            }
        
        key = self.client.create_crypto_key(
            request={
                "parent": key_ring_name,
                "crypto_key_id": key_id,
                "crypto_key": crypto_key,
            }
        )
        
        logger.info(f"Created crypto key: {key_id}")
        
        return KMSKeyMetadata(
            key_id=key.name,
            provider=KMSProvider.GCP,
            region=self.location_id,
            key_spec="SYMMETRIC",
            purpose=purpose,
            created_at=datetime.utcnow(),
            rotation_enabled=rotation_period is not None,
            rotation_period_days=90 if rotation_period else None,
            aliases=[key_id],
        )
    
    def encrypt(
        self,
        key_name: str,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        """Encrypt data using GCP KMS"""
        response = self.client.encrypt(
            request={
                "name": key_name,
                "plaintext": plaintext,
                "additional_authenticated_data": associated_data,
            }
        )
        return response.ciphertext
    
    def decrypt(
        self,
        key_name: str,
        ciphertext: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        """Decrypt data using GCP KMS"""
        response = self.client.decrypt(
            request={
                "name": key_name,
                "ciphertext": ciphertext,
                "additional_authenticated_data": associated_data,
            }
        )
        return response.plaintext
    
    def sign(
        self,
        key_name: str,
        digest: bytes,
    ) -> bytes:
        """Sign digest using GCP KMS asymmetric key"""
        response = self.client.asymmetric_sign(
            request={
                "name": key_name,
                "digest": {"sha256": digest},
            }
        )
        return response.signature

# ============================================
# LOCAL KMS (For development without cloud)
# ============================================

class LocalKMSClient:
    """Local KMS for development when no cloud provider is available"""
    
    def __init__(self, storage_path: str = "local_kms_store"):
        self.storage_path = storage_path
        os.makedirs(storage_path, exist_ok=True)
        self.keys: Dict[str, bytes] = {}
        logger.info(f"Local KMS initialized at {storage_path}")
    
    def create_key(self, alias: str) -> KMSKeyMetadata:
        """Create a local encryption key"""
        key = secrets.token_bytes(32)
        self.keys[alias] = key
        
        with open(os.path.join(self.storage_path, f"{alias}.key"), 'wb') as f:
            f.write(key)
        
        return KMSKeyMetadata(
            key_id=alias,
            provider=KMSProvider.LOCAL,
            key_spec="AES-256",
            purpose="ENCRYPT_DECRYPT",
            aliases=[alias],
        )
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with local key"""
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return len(key).to_bytes(2, 'big') + key + nonce + ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt with local key"""
        key_len = int.from_bytes(ciphertext[:2], 'big')
        key = ciphertext[2:2+key_len]
        nonce = ciphertext[2+key_len:14+key_len]
        encrypted = ciphertext[14+key_len:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, encrypted, None)

# ============================================
# UNIFIED KMS CLIENT
# ============================================

class UnifiedKMSClient:
    """Unified interface for all cloud KMS providers - defaults to LOCAL for development"""
    
    def __init__(self, provider: KMSProvider = None, **kwargs):
        self.provider = provider or KMSProvider.LOCAL
        
        if self.provider == KMSProvider.AWS and AWS_AVAILABLE:
            self.client = AWSKMSClient(**kwargs)
        elif self.provider == KMSProvider.AZURE and AZURE_AVAILABLE:
            self.client = AzureKeyVaultClient(**kwargs)
        elif self.provider == KMSProvider.GCP and GCP_AVAILABLE:
            self.client = GCPKMSClient(**kwargs)
        else:
            if self.provider != KMSProvider.LOCAL:
                logger.warning(f"{self.provider.value} not available, falling back to LOCAL KMS")
            self.client = LocalKMSClient(**kwargs)
            self.provider = KMSProvider.LOCAL
        
        logger.info(f"Unified KMS client initialized with {self.provider.value}")
    
    def encrypt_envelope(
        self,
        key_id: str,
        plaintext: bytes,
        context: Dict[str, str] = None,
    ) -> Tuple[bytes, bytes]:
        """Envelope encryption with KMS"""
        if hasattr(self.client, 'encrypt'):
            return self.client.encrypt(key_id, plaintext, context)
        return (self.client.encrypt(plaintext), b'')
    
    def decrypt_envelope(
        self,
        encrypted_data: bytes,
        context: Dict[str, str] = None,
    ) -> bytes:
        """Envelope decryption with KMS"""
        return self.client.decrypt(encrypted_data, context)
    
    def create_key(self, alias: str, **kwargs) -> KMSKeyMetadata:
        """Create a new key"""
        return self.client.create_key(alias, **kwargs)
    
    def create_hybrid_backed_key(
        self,
        alias: str,
        hybrid_keypair: HybridKeyPair,
    ) -> Tuple[str, bytes]:
        """Create a KMS key that wraps a hybrid keypair for defense-in-depth"""
        encrypted_private, _ = self.encrypt_envelope(
            key_id=alias,
            plaintext=hybrid_keypair.private_seed,
        )
        logger.info(f"Created KMS-backed hybrid key: {alias}")
        return alias, encrypted_private
    
    def unwrap_hybrid_key(
        self,
        encrypted_private: bytes,
        context: Dict[str, str] = None,
    ) -> bytes:
        """Unwrap hybrid private key using KMS"""
        return self.decrypt_envelope(encrypted_private, context)

# ============================================
# KMS KEY ROTATION MANAGER
# ============================================

class KMSRotationManager:
    """Manages automatic key rotation across cloud KMS providers"""
    
    def __init__(self, kms_client: UnifiedKMSClient):
        self.kms_client = kms_client
        self.rotation_schedule: Dict[str, datetime] = {}
        
    def schedule_rotation(self, key_id: str, rotation_days: int = 90):
        """Schedule automatic key rotation"""
        next_rotation = datetime.utcnow() + timedelta(days=rotation_days)
        self.rotation_schedule[key_id] = next_rotation
        logger.info(f"Scheduled rotation for {key_id} in {rotation_days} days")
        
    def check_and_rotate(self) -> Dict[str, str]:
        """Check and perform pending rotations"""
        rotated = {}
        now = datetime.utcnow()
        
        for key_id, rotation_time in list(self.rotation_schedule.items()):
            if now >= rotation_time:
                new_key_id = self._rotate_key(key_id)
                rotated[key_id] = new_key_id
                self.rotation_schedule[new_key_id] = now + timedelta(days=90)
                del self.rotation_schedule[key_id]
        
        return rotated
    
    def _rotate_key(self, old_key_id: str) -> str:
        """Perform key rotation"""
        new_alias = f"{old_key_id}-rotated-{int(datetime.utcnow().timestamp())}"
        logger.info(f"Rotating key {old_key_id} to {new_alias}")
        
        metadata = self.kms_client.create_key(alias=new_alias)
        return metadata.key_id