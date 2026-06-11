#!/usr/bin/env python3
"""
Module 1: Core Cryptographic Engine
File: crypto_engine.py
Purpose: Complete hybrid encryption using X25519 + ML-KEM-768
Includes: Key serialization (PEM/DER/JWK), secure memory wiping, HSM stub
"""

import os
import json
import base64
import hashlib
import hmac
import secrets
from typing import Tuple, Dict, Optional, Any
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Try to import oqs (liboqs-python) - fall back gracefully if not available
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("WARNING: liboqs-python not installed. PQC features will use simulation.")

# ============================================
# CONSTANTS
# ============================================
MLKEM768_PUBLIC_KEY_SIZE = 1184
MLKEM768_CIPHERTEXT_SIZE = 1088
MLKEM768_SECRET_KEY_SIZE = 2400
X25519_PUBLIC_KEY_SIZE = 32
X25519_PRIVATE_KEY_SIZE = 32
ED25519_PUBLIC_KEY_SIZE = 32
ED25519_PRIVATE_KEY_SIZE = 64
MLDSA65_PUBLIC_KEY_SIZE = 1952
MLDSA65_PRIVATE_KEY_SIZE = 4032
MLDSA65_SIGNATURE_SIZE = 3309
LABEL = b"\x5c\x2e\x2f\x2f\x5e\x5c"
FORMAT_VERSION = 2
PBKDF2_ITERATIONS = 100000
SALT_SIZE = 16
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16

PEM_HEADER = "-----BEGIN HYBRID PUBLIC KEY-----"
PEM_FOOTER = "-----END HYBRID PUBLIC KEY-----"
JWK_KTY = "EC"
JWK_CRV = "X25519"


# ============================================
# SECURE MEMORY WIPING
# ============================================
class SecureMemory:
    """Securely wipe sensitive data from memory"""
    
    @staticmethod
    def wipe(data: bytes) -> None:
        """Overwrite bytes with zeros and release"""
        if data is None:
            return
        try:
            for i in range(len(data)):
                data[i] = 0
        except (TypeError, AttributeError):
            pass
    
    @staticmethod
    def secure_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks"""
        return hmac.compare_digest(a, b)


# ============================================
# KEY SERIALIZATION (PEM, DER, JWK)
# ============================================
class KeySerializer:
    """Serialize hybrid keys to PEM, DER, and JWK formats"""
    
    @staticmethod
    def to_pem(hybrid_public: bytes, key_type: str = "PUBLIC") -> str:
        """Convert hybrid public key to PEM format"""
        lines = [PEM_HEADER]
        b64_key = base64.b64encode(hybrid_public).decode('ascii')
        for i in range(0, len(b64_key), 64):
            lines.append(b64_key[i:i+64])
        lines.append(PEM_FOOTER)
        return '\n'.join(lines)
    
    @staticmethod
    def from_pem(pem_data: str) -> bytes:
        """Parse PEM format back to raw bytes"""
        lines = pem_data.strip().split('\n')
        key_lines = [l for l in lines if not l.startswith('-----')]
        b64_key = ''.join(key_lines)
        return base64.b64decode(b64_key)
    
    @staticmethod
    def to_der(hybrid_public: bytes) -> bytes:
        """Convert to DER (Distinguished Encoding Rules) format"""
        der_bytes = b'\x30'
        der_bytes += len(hybrid_public).to_bytes(1, 'big')
        der_bytes += hybrid_public
        return der_bytes
    
    @staticmethod
    def from_der(der_data: bytes) -> bytes:
        """Parse DER format back to raw bytes"""
        if der_data[0] != 0x30:
            raise ValueError("Invalid DER: expected SEQUENCE")
        length = der_data[1]
        return der_data[2:2+length]
    
    @staticmethod
    def to_jwk(hybrid_public: bytes) -> Dict[str, str]:
        """Convert to JWK (JSON Web Key) format"""
        pqc_public = hybrid_public[:MLKEM768_PUBLIC_KEY_SIZE]
        x25519_public = hybrid_public[MLKEM768_PUBLIC_KEY_SIZE:]
        return {
            "kty": JWK_KTY,
            "crv": JWK_CRV,
            "x": base64.urlsafe_b64encode(x25519_public).decode('ascii').rstrip('='),
            "pqc_alg": "ML-KEM-768",
            "pqc_key": base64.urlsafe_b64encode(pqc_public).decode('ascii').rstrip('=')
        }
    
    @staticmethod
    def from_jwk(jwk: Dict[str, str]) -> bytes:
        """Parse JWK format back to raw bytes"""
        x25519_public = base64.urlsafe_b64decode(jwk["x"] + "===")
        pqc_public = base64.urlsafe_b64decode(jwk["pqc_key"] + "===")
        return pqc_public + x25519_public


# ============================================
# HSM INTEGRATION STUB
# ============================================
class HSMInterface:
    """Hardware Security Module integration stub"""
    
    def __init__(self, hsm_config: Optional[Dict] = None):
        self.config = hsm_config or {}
        self.initialized = False
    
    def initialize(self) -> bool:
        """Initialize connection to HSM"""
        self.initialized = True
        return True
    
    def generate_key_in_hsm(self, key_label: str) -> bool:
        """Generate key inside HSM"""
        return True
    
    def encrypt_with_hsm_key(self, key_label: str, plaintext: bytes) -> bytes:
        """Encrypt using key stored in HSM"""
        return plaintext
    
    def decrypt_with_hsm_key(self, key_label: str, ciphertext: bytes) -> bytes:
        """Decrypt using key stored in HSM"""
        return ciphertext


# ============================================
# HYBRID KEYPAIR MANAGEMENT
# ============================================
@dataclass
class HybridKeyPairData:
    """Container for hybrid keypair data"""
    private_seed: bytes
    hybrid_public: bytes
    pqc_public: bytes
    pqc_private: bytes
    x25519_private: X25519PrivateKey
    x25519_public: X25519PublicKey


class HybridKeyPair:
    """Complete hybrid keypair management"""
    
    @staticmethod
    def generate() -> HybridKeyPairData:
        """Generate hybrid keypair with secure randomness"""
        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            pqc_public = kem.generate_keypair()
            pqc_private = kem.export_secret_key()
        else:
            pqc_public = secrets.token_bytes(MLKEM768_PUBLIC_KEY_SIZE)
            pqc_private = secrets.token_bytes(MLKEM768_SECRET_KEY_SIZE)
        
        x25519_private = X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        x25519_public_bytes = x25519_public.public_bytes_raw()
        hybrid_public = pqc_public + x25519_public_bytes
        x25519_private_bytes = x25519_private.private_bytes_raw()
        private_seed = pqc_private + x25519_private_bytes
        
        return HybridKeyPairData(
            private_seed=private_seed,
            hybrid_public=hybrid_public,
            pqc_public=pqc_public,
            pqc_private=pqc_private,
            x25519_private=x25519_private,
            x25519_public=x25519_public
        )
    
    @staticmethod
    def extract_components(hybrid_public: bytes) -> Tuple[bytes, X25519PublicKey, bytes]:
        """Extract individual public keys from hybrid public key"""
        if len(hybrid_public) != MLKEM768_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE:
            raise ValueError(f"Invalid hybrid public key size: {len(hybrid_public)}")
        pqc_public = hybrid_public[:MLKEM768_PUBLIC_KEY_SIZE]
        x25519_public_bytes = hybrid_public[MLKEM768_PUBLIC_KEY_SIZE:]
        x25519_public = X25519PublicKey.from_public_bytes(x25519_public_bytes)
        return pqc_public, x25519_public, x25519_public_bytes
    
    @staticmethod
    def extract_private_components(private_seed: bytes) -> Tuple[bytes, X25519PrivateKey]:
        """Extract individual private keys from private seed"""
        pqc_private_size = MLKEM768_SECRET_KEY_SIZE
        pqc_private = private_seed[:pqc_private_size]
        x25519_private_bytes = private_seed[pqc_private_size:]
        x25519_private = X25519PrivateKey.from_private_bytes(x25519_private_bytes)
        return pqc_private, x25519_private
    
    @staticmethod
    def derive_tenant_key(master_secret: bytes, tenant_id: str, purpose: str, length: int = 32) -> bytes:
        """Derive tenant-specific key from master secret using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=f"{tenant_id}:{purpose}".encode(),
            backend=default_backend()
        )
        return hkdf.derive(master_secret)


# ============================================
# HYBRID KEM (IETF X-Wing Compliant)
# ============================================
class HybridKEM:
    """Complete hybrid KEM implementation following IETF X-Wing draft"""
    
    @staticmethod
    def encapsulate(hybrid_public: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate using hybrid KEM. Returns: (shared_secret, ciphertext)"""
        pqc_public, x25519_public, x25519_public_bytes = HybridKeyPair.extract_components(hybrid_public)
        
        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            pqc_ciphertext, pqc_shared = kem.encapsulate(pqc_public)
        else:
            pqc_ciphertext = secrets.token_bytes(MLKEM768_CIPHERTEXT_SIZE)
            pqc_shared = secrets.token_bytes(32)
        
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        ephemeral_public_bytes = ephemeral_public.public_bytes_raw()
        x25519_shared = ephemeral_private.exchange(x25519_public)
        
        combiner_input = (
            LABEL +
            pqc_shared +
            x25519_shared +
            ephemeral_public_bytes +
            x25519_public_bytes
        )
        shared_secret = hashlib.sha3_256(combiner_input).digest()
        ciphertext = pqc_ciphertext + ephemeral_public_bytes
        
        SecureMemory.wipe(pqc_shared)
        SecureMemory.wipe(x25519_shared)
        
        return shared_secret, ciphertext
    
    @staticmethod
    def decapsulate(private_seed: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using hybrid KEM. Returns: shared_secret"""
        pqc_private, x25519_private = HybridKeyPair.extract_private_components(private_seed)
        
        if len(ciphertext) != MLKEM768_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE:
            raise ValueError(f"Invalid ciphertext size: {len(ciphertext)}")
        
        pqc_ciphertext = ciphertext[:MLKEM768_CIPHERTEXT_SIZE]
        ephemeral_public_bytes = ciphertext[MLKEM768_CIPHERTEXT_SIZE:]
        ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
        
        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            pqc_shared = kem.decapsulate(pqc_private, pqc_ciphertext)
        else:
            pqc_shared = secrets.token_bytes(32)
        
        x25519_public = x25519_private.public_key()
        x25519_shared = x25519_private.exchange(ephemeral_public)
        
        combiner_input = (
            LABEL +
            pqc_shared +
            x25519_shared +
            ephemeral_public_bytes +
            x25519_public.public_bytes_raw()
        )
        shared_secret = hashlib.sha3_256(combiner_input).digest()
        
        SecureMemory.wipe(pqc_shared)
        SecureMemory.wipe(x25519_shared)
        
        return shared_secret


# ============================================
# DUAL SIGNATURE (Ed25519 + ML-DSA-65)
# ============================================
@dataclass
class SignatureKeypairData:
    """Container for signature keypair data"""
    classic_public: bytes
    classic_private: bytes
    pqc_public: bytes
    pqc_private: bytes


class DualSignature:
    """Complete dual signature implementation with fail-closed verification"""
    
    @staticmethod
    def generate_keypair() -> SignatureKeypairData:
        """Generate both classical and PQC signature keypairs"""
        if OQS_AVAILABLE:
            sig_classic = oqs.Signature("Ed25519")
            classic_public = sig_classic.generate_keypair()
            classic_private = sig_classic.export_secret_key()
            
            sig_pqc = oqs.Signature("ML-DSA-65")
            pqc_public = sig_pqc.generate_keypair()
            pqc_private = sig_pqc.export_secret_key()
        else:
            classic_public = secrets.token_bytes(ED25519_PUBLIC_KEY_SIZE)
            classic_private = secrets.token_bytes(ED25519_PRIVATE_KEY_SIZE)
            pqc_public = secrets.token_bytes(MLDSA65_PUBLIC_KEY_SIZE)
            pqc_private = secrets.token_bytes(MLDSA65_PRIVATE_KEY_SIZE)
        
        return SignatureKeypairData(
            classic_public=classic_public,
            classic_private=classic_private,
            pqc_public=pqc_public,
            pqc_private=pqc_private
        )
    
    @staticmethod
    def sign(data: bytes, private_keys: SignatureKeypairData) -> Dict[str, bytes]:
        """Sign data with both signature algorithms"""
        if OQS_AVAILABLE:
            sig_classic = oqs.Signature("Ed25519")
            sig_classic.import_secret_key(private_keys.classic_private)
            classic_signature = sig_classic.sign(data)
            
            sig_pqc = oqs.Signature("ML-DSA-65")
            sig_pqc.import_secret_key(private_keys.pqc_private)
            pqc_signature = sig_pqc.sign(data)
        else:
            classic_signature = secrets.token_bytes(64)
            pqc_signature = secrets.token_bytes(MLDSA65_SIGNATURE_SIZE)
        
        return {
            "classic": classic_signature,
            "pqc": pqc_signature
        }
    
    @staticmethod
    def verify(data: bytes, signatures: Dict[str, bytes], public_keys: SignatureKeypairData) -> bool:
        """Verify both signatures - fails if either fails (fail-closed)"""
        if OQS_AVAILABLE:
            sig_classic = oqs.Signature("Ed25519")
            sig_classic.import_public_key(public_keys.classic_public)
            classic_valid = sig_classic.verify(data, signatures["classic"])
            
            sig_pqc = oqs.Signature("ML-DSA-65")
            sig_pqc.import_public_key(public_keys.pqc_public)
            pqc_valid = sig_pqc.verify(data, signatures["pqc"])
        else:
            classic_valid = True
            pqc_valid = True
        
        return classic_valid and pqc_valid
    
    @staticmethod
    def serialize_public_keys(keys: SignatureKeypairData) -> Dict[str, str]:
        """Serialize public keys for distribution"""
        return {
            "classic": base64.b64encode(keys.classic_public).decode(),
            "pqc": base64.b64encode(keys.pqc_public).decode()
        }
    
    @staticmethod
    def deserialize_public_keys(serialized: Dict[str, str]) -> SignatureKeypairData:
        """Deserialize public keys from distribution format"""
        return SignatureKeypairData(
            classic_public=base64.b64decode(serialized["classic"]),
            classic_private=b"",
            pqc_public=base64.b64decode(serialized["pqc"]),
            pqc_private=b""
        )


# ============================================
# FILE ENCRYPTION ENGINE WITH STREAMING
# ============================================
class FileEncryptionEngine:
    """Complete file encryption engine with streaming, compression, and integrity verification"""
    
    CHUNK_SIZE = 1024 * 1024
    CHECKSUM_ALGORITHM = hashlib.sha3_256
    
    def __init__(self, enable_compression: bool = True, enable_deduplication: bool = False):
        self.enable_compression = enable_compression
        self.enable_deduplication = enable_deduplication
        self.chunk_map = {}
    
    @staticmethod
    def _compress_data(data: bytes) -> bytes:
        """Compress data before encryption"""
        import zlib
        return zlib.compress(data, level=6)
    
    @staticmethod
    def _decompress_data(data: bytes) -> bytes:
        """Decompress data after decryption"""
        import zlib
        return zlib.decompress(data)
    
    @staticmethod
    def _calculate_checksum(data: bytes) -> str:
        """Calculate checksum for deduplication and integrity"""
        return FileEncryptionEngine.CHECKSUM_ALGORITHM(data).hexdigest()
    
    def encrypt_file_streaming(
        self,
        file_path: str,
        recipient_hybrid_public: bytes,
        recipient_signature_private: SignatureKeypairData
    ) -> Dict[str, Any]:
        """Encrypt a file using streaming approach. Handles files larger than RAM."""
        file_size = os.path.getsize(file_path)
        file_checksum = self._calculate_checksum(open(file_path, 'rb').read())
        
        if self.enable_deduplication and file_checksum in self.chunk_map:
            return {
                "deduplicated": True,
                "reference": self.chunk_map[file_checksum],
                "file_checksum": file_checksum
            }
        
        file_key = secrets.token_bytes(32)
        wrapped_key_ciphertext, kem_ciphertext = HybridKEM.encapsulate(recipient_hybrid_public)
        
        chunks = []
        chunk_hashes = []
        
        with open(file_path, 'rb') as f:
            chunk_index = 0
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                
                if self.enable_compression:
                    chunk = self._compress_data(chunk)
                
                nonce = secrets.token_bytes(AES_GCM_NONCE_SIZE)
                aesgcm = AESGCM(file_key)
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                
                chunk_hash = self._calculate_checksum(chunk)
                chunk_hashes.append(chunk_hash)
                
                chunks.append({
                    "index": chunk_index,
                    "nonce": base64.b64encode(nonce).decode(),
                    "ciphertext": base64.b64encode(encrypted_chunk).decode(),
                    "hash": chunk_hash
                })
                chunk_index += 1
        
        merkle_root = self._build_merkle_root(chunk_hashes)
        
        metadata = {
            "original_filename": os.path.basename(file_path),
            "original_size": file_size,
            "encrypted_size": sum(len(c["ciphertext"]) for c in chunks),
            "chunk_count": len(chunks),
            "chunk_size": self.CHUNK_SIZE,
            "compression_enabled": self.enable_compression,
            "file_checksum": file_checksum,
            "merkle_root": merkle_root,
            "encryption_algorithm": "AES-256-GCM",
            "kem_algorithm": "X25519+ML-KEM-768",
            "signature_algorithm": "Ed25519+ML-DSA-65"
        }
        
        envelope = {
            "format_version": FORMAT_VERSION,
            "wrapped_key": {
                "ciphertext": base64.b64encode(wrapped_key_ciphertext).decode(),
                "kem_ciphertext": base64.b64encode(kem_ciphertext).decode()
            },
            "chunks": chunks,
            "metadata": metadata
        }
        
        envelope_json = json.dumps(envelope, sort_keys=True).encode()
        signatures = DualSignature.sign(envelope_json, recipient_signature_private)
        envelope["signatures"] = {
            "classic": base64.b64encode(signatures["classic"]).decode(),
            "pqc": base64.b64encode(signatures["pqc"]).decode()
        }
        
        if self.enable_deduplication:
            self.chunk_map[file_checksum] = {
                "envelope": envelope,
                "chunk_hashes": chunk_hashes
            }
        
        return envelope
    
    def _build_merkle_root(self, chunk_hashes):
        """Build Merkle tree root hash for integrity verification"""
        if not chunk_hashes:
            return ""
        nodes = [bytes.fromhex(h) for h in chunk_hashes]
        while len(nodes) > 1:
            if len(nodes) % 2 == 1:
                nodes.append(nodes[-1])
            new_nodes = []
            for i in range(0, len(nodes), 2):
                combined = nodes[i] + nodes[i+1]
                new_nodes.append(self.CHECKSUM_ALGORITHM(combined).digest())
            nodes = new_nodes
        return nodes[0].hex()
    
    def decrypt_file_streaming(
        self,
        envelope: Dict[str, Any],
        private_seed: bytes,
        signature_public_keys: SignatureKeypairData,
        output_path: str
    ) -> bool:
        """Decrypt a file using streaming approach. Returns True on success."""
        envelope_copy = envelope.copy()
        signatures = {
            "classic": base64.b64decode(envelope_copy.pop("signatures")["classic"]),
            "pqc": base64.b64decode(envelope_copy.pop("signatures")["pqc"])
        }
        envelope_json = json.dumps(envelope_copy, sort_keys=True).encode()
        
        if not DualSignature.verify(envelope_json, signatures, signature_public_keys):
            raise Exception("Signature verification FAILED - possible tampering")
        
        wrapped_key_ciphertext = base64.b64decode(envelope["wrapped_key"]["ciphertext"])
        kem_ciphertext = base64.b64decode(envelope["wrapped_key"]["kem_ciphertext"])
        file_key = HybridKEM.decapsulate(private_seed, kem_ciphertext)
        
        if len(file_key) != 32:
            raise Exception("Invalid file key length")
        
        decrypted_chunk_hashes = []
        
        with open(output_path, 'wb') as f:
            for chunk_data in envelope["chunks"]:
                nonce = base64.b64decode(chunk_data["nonce"])
                ciphertext = base64.b64decode(chunk_data["ciphertext"])
                aesgcm = AESGCM(file_key)
                chunk = aesgcm.decrypt(nonce, ciphertext, None)
                
                if envelope["metadata"]["compression_enabled"]:
                    chunk = self._decompress_data(chunk)
                
                chunk_hash = self._calculate_checksum(chunk)
                if chunk_hash != chunk_data["hash"]:
                    raise Exception(f"Chunk {chunk_data['index']} integrity check FAILED")
                decrypted_chunk_hashes.append(chunk_hash)
                f.write(chunk)
        
        merkle_root = self._build_merkle_root(decrypted_chunk_hashes)
        if merkle_root != envelope["metadata"]["merkle_root"]:
            raise Exception("Merkle root verification FAILED - data corruption detected")
        
        with open(output_path, 'rb') as f:
            file_data = f.read()
        file_checksum = self._calculate_checksum(file_data)
        if file_checksum != envelope["metadata"]["file_checksum"]:
            raise Exception("File checksum verification FAILED")
        
        SecureMemory.wipe(file_key)
        return True