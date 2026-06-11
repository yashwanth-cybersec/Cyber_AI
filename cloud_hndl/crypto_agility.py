#!/usr/bin/env python3
"""
Module: Cryptographic Agility
File: crypto_agility.py
Purpose: Runtime algorithm switching and migration
Supports: Multiple algorithms with seamless transitions
"""

import json
import hashlib
import secrets
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519
from cryptography.hazmat.primitives import hashes, serialization
import oqs

from .logging_config import get_logger

logger = get_logger(__name__)

# ============================================
# ALGORITHM REGISTRY
# ============================================

class AlgorithmCategory(Enum):
    KEY_ENCAPSULATION = "kem"
    SIGNATURE = "signature"
    ENCRYPTION = "encryption"
    HASH = "hash"

class AlgorithmStatus(Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    LEGACY = "legacy"
    EXPERIMENTAL = "experimental"
    DISABLED = "disabled"

@dataclass
class AlgorithmInfo:
    """Information about a cryptographic algorithm"""
    name: str
    category: AlgorithmCategory
    status: AlgorithmStatus
    security_level: int  # 128, 192, 256 bits
    is_post_quantum: bool
    is_hybrid_capable: bool
    deprecation_date: Optional[datetime] = None
    successor: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class AlgorithmRegistry:
    """Central registry of supported algorithms"""
    
    ALGORITHMS: Dict[str, AlgorithmInfo] = {
        # KEM Algorithms
        "ML-KEM-512": AlgorithmInfo(
            name="ML-KEM-512",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            status=AlgorithmStatus.ACTIVE,
            security_level=128,
            is_post_quantum=True,
            is_hybrid_capable=True,
        ),
        "ML-KEM-768": AlgorithmInfo(
            name="ML-KEM-768",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            status=AlgorithmStatus.ACTIVE,
            security_level=192,
            is_post_quantum=True,
            is_hybrid_capable=True,
        ),
        "ML-KEM-1024": AlgorithmInfo(
            name="ML-KEM-1024",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            status=AlgorithmStatus.ACTIVE,
            security_level=256,
            is_post_quantum=True,
            is_hybrid_capable=True,
        ),
        "X25519": AlgorithmInfo(
            name="X25519",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            status=AlgorithmStatus.ACTIVE,
            security_level=128,
            is_post_quantum=False,
            is_hybrid_capable=True,
        ),
        "RSA-2048": AlgorithmInfo(
            name="RSA-2048",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            status=AlgorithmStatus.DEPRECATED,
            security_level=112,
            is_post_quantum=False,
            is_hybrid_capable=False,
            deprecation_date=datetime(2025, 1, 1),
            successor="ML-KEM-768+X25519",
        ),
        "RSA-4096": AlgorithmInfo(
            name="RSA-4096",
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            status=AlgorithmStatus.LEGACY,
            security_level=140,
            is_post_quantum=False,
            is_hybrid_capable=False,
            successor="ML-KEM-1024+X25519",
        ),
        
        # Signature Algorithms
        "ML-DSA-44": AlgorithmInfo(
            name="ML-DSA-44",
            category=AlgorithmCategory.SIGNATURE,
            status=AlgorithmStatus.ACTIVE,
            security_level=128,
            is_post_quantum=True,
            is_hybrid_capable=True,
        ),
        "ML-DSA-65": AlgorithmInfo(
            name="ML-DSA-65",
            category=AlgorithmCategory.SIGNATURE,
            status=AlgorithmStatus.ACTIVE,
            security_level=192,
            is_post_quantum=True,
            is_hybrid_capable=True,
        ),
        "ML-DSA-87": AlgorithmInfo(
            name="ML-DSA-87",
            category=AlgorithmCategory.SIGNATURE,
            status=AlgorithmStatus.ACTIVE,
            security_level=256,
            is_post_quantum=True,
            is_hybrid_capable=True,
        ),
        "Ed25519": AlgorithmInfo(
            name="Ed25519",
            category=AlgorithmCategory.SIGNATURE,
            status=AlgorithmStatus.ACTIVE,
            security_level=128,
            is_post_quantum=False,
            is_hybrid_capable=True,
        ),
        "ECDSA-P256": AlgorithmInfo(
            name="ECDSA-P256",
            category=AlgorithmCategory.SIGNATURE,
            status=AlgorithmStatus.DEPRECATED,
            security_level=128,
            is_post_quantum=False,
            is_hybrid_capable=False,
            deprecation_date=datetime(2026, 1, 1),
            successor="ML-DSA-44+Ed25519",
        ),
        "RSA-PSS-2048": AlgorithmInfo(
            name="RSA-PSS-2048",
            category=AlgorithmCategory.SIGNATURE,
            status=AlgorithmStatus.LEGACY,
            security_level=112,
            is_post_quantum=False,
            is_hybrid_capable=False,
            successor="ML-DSA-65+Ed25519",
        ),
    }
    
    @classmethod
    def get_active_kem_algorithms(cls) -> List[str]:
        """Get list of active KEM algorithms"""
        return [
            name for name, info in cls.ALGORITHMS.items()
            if info.category == AlgorithmCategory.KEY_ENCAPSULATION
            and info.status == AlgorithmStatus.ACTIVE
        ]
    
    @classmethod
    def get_active_signature_algorithms(cls) -> List[str]:
        """Get list of active signature algorithms"""
        return [
            name for name, info in cls.ALGORITHMS.items()
            if info.category == AlgorithmCategory.SIGNATURE
            and info.status == AlgorithmStatus.ACTIVE
        ]
    
    @classmethod
    def get_hybrid_pairs(cls) -> List[Tuple[str, str]]:
        """Get recommended hybrid algorithm pairs"""
        return [
            ("ML-KEM-768", "X25519"),
            ("ML-KEM-1024", "X25519"),
            ("ML-DSA-65", "Ed25519"),
            ("ML-DSA-87", "Ed25519"),
        ]
    
    @classmethod
    def is_deprecated(cls, algorithm: str) -> bool:
        """Check if algorithm is deprecated"""
        info = cls.ALGORITHMS.get(algorithm)
        return info and info.status in [AlgorithmStatus.DEPRECATED, AlgorithmStatus.LEGACY]
    
    @classmethod
    def get_successor(cls, algorithm: str) -> Optional[str]:
        """Get recommended successor for deprecated algorithm"""
        info = cls.ALGORITHMS.get(algorithm)
        return info.successor if info else None

# ============================================
# ALGORITHM MIGRATION ENGINE
# ============================================

@dataclass
class MigrationPolicy:
    """Policy for algorithm migration"""
    allow_deprecated: bool = False
    auto_upgrade: bool = True
    minimum_security_level: int = 128
    prefer_post_quantum: bool = True
    notification_days: int = 30

class CryptoAgilityManager:
    """Manages cryptographic algorithm agility and migration"""
    
    def __init__(self, policy: MigrationPolicy = None):
        self.policy = policy or MigrationPolicy()
        self.registry = AlgorithmRegistry()
        self.migration_history: List[Dict] = []
        self.active_algorithms: Dict[str, str] = {}  # purpose -> algorithm
        
    def select_algorithm(
        self,
        category: AlgorithmCategory,
        required_security_level: int = 128,
        prefer_hybrid: bool = True,
    ) -> str:
        """Select best algorithm based on policy"""
        candidates = []
        
        for name, info in self.registry.ALGORITHMS.items():
            if info.category != category:
                continue
            if info.status == AlgorithmStatus.DISABLED:
                continue
            if info.status in [AlgorithmStatus.DEPRECATED, AlgorithmStatus.LEGACY]:
                if not self.policy.allow_deprecated:
                    continue
            if info.security_level < max(required_security_level, self.policy.minimum_security_level):
                continue
            if self.policy.prefer_post_quantum and not info.is_post_quantum:
                continue
                
            candidates.append((name, info))
        
        if not candidates:
            raise ValueError(f"No suitable algorithm for {category}")
        
        # Sort by: hybrid capable, security level, post-quantum
        candidates.sort(key=lambda x: (
            x[1].is_hybrid_capable if prefer_hybrid else False,
            x[1].security_level,
            x[1].is_post_quantum,
        ), reverse=True)
        
        return candidates[0][0]
    
    def generate_keypair(self, algorithm: str) -> Tuple[bytes, bytes]:
        """Generate keypair using specified algorithm"""
        info = self.registry.ALGORITHMS.get(algorithm)
        if not info:
            raise ValueError(f"Unknown algorithm: {algorithm}")
            
        logger.info(f"Generating keypair with {algorithm}")
        
        if algorithm.startswith("ML-KEM"):
            kem = oqs.KeyEncapsulation(algorithm)
            public = kem.generate_keypair()
            private = kem.export_secret_key()
            return public, private
            
        elif algorithm == "X25519":
            private = x25519.X25519PrivateKey.generate()
            public = private.public_key()
            return (
                public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw),
                private.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
            )
            
        elif algorithm.startswith("ML-DSA"):
            sig = oqs.Signature(algorithm)
            public = sig.generate_keypair()
            private = sig.export_secret_key()
            return public, private
            
        elif algorithm == "Ed25519":
            from cryptography.hazmat.primitives.asymmetric import ed25519
            private = ed25519.Ed25519PrivateKey.generate()
            public = private.public_key()
            return (
                public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw),
                private.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
            )
            
        elif algorithm.startswith("RSA"):
            key_size = int(algorithm.split("-")[1])
            private = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            public = private.public_key()
            return (
                public.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo),
                private.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
            )
            
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def migrate_key(
        self,
        old_algorithm: str,
        old_public_key: bytes,
        old_private_key: bytes,
        new_algorithm: str = None,
    ) -> Tuple[str, bytes, bytes]:
        """Migrate key to new algorithm"""
        if not new_algorithm:
            new_algorithm = self.registry.get_successor(old_algorithm)
            if not new_algorithm:
                new_algorithm = self.select_algorithm(
                    self.registry.ALGORITHMS[old_algorithm].category
                )
        
        logger.info(f"Migrating from {old_algorithm} to {new_algorithm}")
        
        # Generate new keypair
        new_public, new_private = self.generate_keypair(new_algorithm)
        
        # Record migration
        self.migration_history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "old_algorithm": old_algorithm,
            "new_algorithm": new_algorithm,
            "old_public_fingerprint": hashlib.sha256(old_public_key).hexdigest()[:16],
            "new_public_fingerprint": hashlib.sha256(new_public).hexdigest()[:16],
        })
        
        return new_algorithm, new_public, new_private
    
    def rewrap_data(
        self,
        ciphertext: bytes,
        old_algorithm: str,
        old_private_key: bytes,
        new_public_key: bytes,
        new_algorithm: str,
    ) -> bytes:
        """Rewrap data with new algorithm"""
        logger.info(f"Rewrapping data from {old_algorithm} to {new_algorithm}")
        
        # Decrypt with old key
        if old_algorithm.startswith("ML-KEM"):
            kem = oqs.KeyEncapsulation(old_algorithm)
            plaintext = kem.decapsulate(old_private_key, ciphertext)
        elif old_algorithm == "X25519":
            private = x25519.X25519PrivateKey.from_private_bytes(old_private_key)
            peer_public = x25519.X25519PublicKey.from_public_bytes(ciphertext[:32])
            plaintext = private.exchange(peer_public)
        else:
            raise ValueError(f"Cannot rewrap from {old_algorithm}")
        
        # Encrypt with new key
        if new_algorithm.startswith("ML-KEM"):
            kem = oqs.KeyEncapsulation(new_algorithm)
            new_ciphertext, _ = kem.encapsulate(new_public_key)
        elif new_algorithm == "X25519":
            ephemeral = x25519.X25519PrivateKey.generate()
            new_ciphertext = ephemeral.public_key().public_bytes_raw()
        else:
            raise ValueError(f"Cannot rewrap to {new_algorithm}")
        
        return new_ciphertext
    
    def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status"""
        deprecated_in_use = [
            algo for algo in self.active_algorithms.values()
            if self.registry.is_deprecated(algo)
        ]
        
        upcoming_deprecations = []
        for name, info in self.registry.ALGORITHMS.items():
            if info.deprecation_date:
                days_until = (info.deprecation_date - datetime.now()).days
                if 0 <= days_until <= self.policy.notification_days:
                    upcoming_deprecations.append({
                        "algorithm": name,
                        "days_until": days_until,
                        "successor": info.successor,
                    })
        
        return {
            "active_algorithms": self.active_algorithms.copy(),
            "deprecated_in_use": deprecated_in_use,
            "upcoming_deprecations": upcoming_deprecations,
            "migration_count": len(self.migration_history),
            "last_migration": self.migration_history[-1] if self.migration_history else None,
            "policy": {
                "allow_deprecated": self.policy.allow_deprecated,
                "auto_upgrade": self.policy.auto_upgrade,
                "minimum_security_level": self.policy.minimum_security_level,
            }
        }
    
    def health_check(self) -> Dict[str, Any]:
        """Check cryptographic health"""
        issues = []
        warnings = []
        
        for purpose, algorithm in self.active_algorithms.items():
            if self.registry.is_deprecated(algorithm):
                issues.append({
                    "severity": "high",
                    "purpose": purpose,
                    "algorithm": algorithm,
                    "message": f"Using deprecated algorithm: {algorithm}",
                    "recommendation": self.registry.get_successor(algorithm),
                })
            
            info = self.registry.ALGORITHMS.get(algorithm)
            if info and info.security_level < self.policy.minimum_security_level:
                warnings.append({
                    "severity": "medium",
                    "purpose": purpose,
                    "algorithm": algorithm,
                    "message": f"Security level {info.security_level} below minimum {self.policy.minimum_security_level}",
                })
        
        return {
            "healthy": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "recommendations": [
                {
                    "purpose": "kem",
                    "recommended": self.select_algorithm(AlgorithmCategory.KEY_ENCAPSULATION),
                },
                {
                    "purpose": "signature",
                    "recommended": self.select_algorithm(AlgorithmCategory.SIGNATURE),
                }
            ]
        }

# ============================================
# VERSIONED CRYPTO
# ============================================

class VersionedCrypto:
    """Versioned cryptographic operations for backward compatibility"""
    
    VERSION_MARKERS = {
        1: b"\x01",  # Legacy RSA-2048
        2: b"\x02",  # ECDSA-P256
        3: b"\x03",  # X25519 + Ed25519
        4: b"\x04",  # ML-KEM-768 + ML-DSA-65
        5: b"\x05",  # Hybrid (X25519 + ML-KEM-768)
    }
    
    def __init__(self):
        self.agility = CryptoAgilityManager()
        self.current_version = 5
        
    def encrypt_with_version(self, plaintext: bytes, public_key: bytes, algorithm: str) -> bytes:
        """Encrypt with version marker for future compatibility"""
        version_marker = self.VERSION_MARKERS[self.current_version]
        
        if algorithm.startswith("ML-KEM"):
            kem = oqs.KeyEncapsulation(algorithm)
            ciphertext, shared_secret = kem.encapsulate(public_key)
            
        elif algorithm == "X25519":
            private = x25519.X25519PrivateKey.generate()
            ciphertext = private.public_key().public_bytes_raw()
            peer_public = x25519.X25519PublicKey.from_public_bytes(public_key)
            shared_secret = private.exchange(peer_public)
            
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Derive encryption key
        key = hashlib.sha256(shared_secret + b"encryption").digest()
        nonce = secrets.token_bytes(12)
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, plaintext, version_marker)
        
        # Format: version (1) + ciphertext_len (2) + ciphertext + nonce (12) + encrypted
        import struct
        return (
            version_marker +
            struct.pack(">H", len(ciphertext)) +
            ciphertext +
            nonce +
            encrypted
        )
    
    def decrypt_with_version(self, encrypted_data: bytes, private_key: bytes, algorithm: str) -> bytes:
        """Decrypt based on version marker"""
        version_marker = encrypted_data[0:1]
        version = next((v for v, m in self.VERSION_MARKERS.items() if m == version_marker), None)
        
        if not version:
            raise ValueError(f"Unknown version marker: {version_marker}")
            
        import struct
        ciphertext_len = struct.unpack(">H", encrypted_data[1:3])[0]
        ciphertext = encrypted_data[3:3+ciphertext_len]
        nonce = encrypted_data[3+ciphertext_len:15+ciphertext_len]
        encrypted = encrypted_data[15+ciphertext_len:]
        
        # Decapsulate
        if algorithm.startswith("ML-KEM"):
            kem = oqs.KeyEncapsulation(algorithm)
            shared_secret = kem.decapsulate(private_key, ciphertext)
        elif algorithm == "X25519":
            private = x25519.X25519PrivateKey.from_private_bytes(private_key)
            peer_public = x25519.X25519PublicKey.from_public_bytes(ciphertext)
            shared_secret = private.exchange(peer_public)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Derive decryption key
        key = hashlib.sha256(shared_secret + b"encryption").digest()
        
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, encrypted, version_marker)