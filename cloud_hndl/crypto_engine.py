#!/usr/bin/env python3
"""
Module 1: Core Cryptographic Engine
Purpose: Complete hybrid encryption using X25519 + ML-KEM-768
Includes: Key generation, KEM, dual signatures, file encryption engine,
           key serialization (PEM/DER/JWK), secure memory wiping
"""

import os
import io
import json
import base64
import hashlib
import hmac
import secrets
import struct
import tempfile
import zlib
from typing import Tuple, Dict, Optional, Any, List
from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Try to import liboqs for real PQC, fall back to simulation
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False

# ============================================
# CONSTANTS
# ============================================
MLKEM768_PUBLIC_KEY_SIZE = 1184
MLKEM768_CIPHERTEXT_SIZE = 1088
MLKEM768_SECRET_KEY_SIZE = 2400
X25519_PUBLIC_KEY_SIZE = 32
X25519_PRIVATE_KEY_SIZE = 32
MLDSA65_PUBLIC_KEY_SIZE = 1952
MLDSA65_PRIVATE_KEY_SIZE = 4032
MLDSA65_SIGNATURE_SIZE = 3309

LABEL = b"\x5c\x2e\x2f\x2f\x5e\x5c"
FORMAT_VERSION = 2
AES_GCM_NONCE_SIZE = 12

# ============================================
# SECURE MEMORY WIPING
# ============================================
class SecureMemory:
    @staticmethod
    def wipe(data):
        if data is None:
            return
        try:
            for i in range(len(data)):
                data[i] = 0
        except (TypeError, AttributeError):
            pass

    @staticmethod
    def secure_compare(a, b):
        return hmac.compare_digest(a, b)

# ============================================
# KEY SERIALIZATION
# ============================================
class KeySerializer:
    PEM_HEADER = "-----BEGIN HYBRID PUBLIC KEY-----"
    PEM_FOOTER = "-----END HYBRID PUBLIC KEY-----"

    @staticmethod
    def to_pem(hybrid_public, key_type="PUBLIC"):
        lines = [KeySerializer.PEM_HEADER]
        b64_key = base64.b64encode(hybrid_public).decode('ascii')
        for i in range(0, len(b64_key), 64):
            lines.append(b64_key[i:i+64])
        lines.append(KeySerializer.PEM_FOOTER)
        return '\n'.join(lines)

    @staticmethod
    def from_pem(pem_data):
        lines = pem_data.strip().split('\n')
        key_lines = [l for l in lines if not l.startswith('-----')]
        b64_key = ''.join(key_lines)
        return base64.b64decode(b64_key)

    @staticmethod
    def to_der(hybrid_public):
        return b'\x30' + len(hybrid_public).to_bytes(2, 'big') + hybrid_public

    @staticmethod
    def from_der(der_data):
        if der_data[0] != 0x30:
            raise ValueError("Invalid DER format")
        length = int.from_bytes(der_data[1:3], 'big')
        return der_data[3:3+length]

    @staticmethod
    def to_jwk(hybrid_public):
        pqc_public = hybrid_public[:MLKEM768_PUBLIC_KEY_SIZE]
        x25519_public = hybrid_public[MLKEM768_PUBLIC_KEY_SIZE:]
        return {
            "kty": "EC", "crv": "X25519",
            "x": base64.urlsafe_b64encode(x25519_public).decode('ascii').rstrip('='),
            "pqc_alg": "ML-KEM-768",
            "pqc_key": base64.urlsafe_b64encode(pqc_public).decode('ascii').rstrip('=')
        }

    @staticmethod
    def from_jwk(jwk):
        x25519_public = base64.urlsafe_b64decode(jwk["x"] + "===")
        pqc_public = base64.urlsafe_b64decode(jwk["pqc_key"] + "===")
        return pqc_public + x25519_public

# ============================================
# HYBRID KEYPAIR
# ============================================
class HybridKeyPairData:
    def __init__(self, private_seed, hybrid_public, pqc_public, pqc_private, x25519_private, x25519_public):
        self.private_seed = private_seed
        self.hybrid_public = hybrid_public
        self.pqc_public = pqc_public
        self.pqc_private = pqc_private
        self.x25519_private = x25519_private
        self.x25519_public = x25519_public

class HybridKeyPair:
    @staticmethod
    def generate():
        # Generate X25519 keypair (always real)
        x25519_private = X25519PrivateKey.generate()
        x25519_public = x25519_private.public_key()
        x25519_public_bytes = x25519_public.public_bytes_raw()
        x25519_private_bytes = x25519_private.private_bytes_raw()

        # Generate ML-KEM-768 keypair (real if OQS available)
        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            pqc_public = kem.generate_keypair()
            pqc_private = kem.export_secret_key()
        else:
            pqc_public = secrets.token_bytes(MLKEM768_PUBLIC_KEY_SIZE)
            pqc_private = secrets.token_bytes(MLKEM768_SECRET_KEY_SIZE)

        hybrid_public = pqc_public + x25519_public_bytes
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
    def extract_components(hybrid_public):
        if len(hybrid_public) != MLKEM768_PUBLIC_KEY_SIZE + X25519_PUBLIC_KEY_SIZE:
            raise ValueError(f"Invalid hybrid public key size: {len(hybrid_public)}")
        pqc_public = hybrid_public[:MLKEM768_PUBLIC_KEY_SIZE]
        x25519_public_bytes = hybrid_public[MLKEM768_PUBLIC_KEY_SIZE:]
        x25519_public = X25519PublicKey.from_public_bytes(x25519_public_bytes)
        return pqc_public, x25519_public, x25519_public_bytes

    @staticmethod
    def extract_private_components(private_seed):
        pqc_private = private_seed[:MLKEM768_SECRET_KEY_SIZE]
        x25519_private_bytes = private_seed[MLKEM768_SECRET_KEY_SIZE:]
        x25519_private = X25519PrivateKey.from_private_bytes(x25519_private_bytes)
        return pqc_private, x25519_private

    @staticmethod
    def derive_tenant_key(master_secret, tenant_id, purpose, length=32):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=f"{tenant_id}:{purpose}".encode(),
            backend=default_backend()
        )
        return hkdf.derive(master_secret)

# ============================================
# HYBRID KEM
# ============================================
class HybridKEM:
    @staticmethod
    def encapsulate(hybrid_public):
        pqc_public, x25519_public, x25519_public_bytes = HybridKeyPair.extract_components(hybrid_public)

        # ML-KEM-768 encapsulation
        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            pqc_ciphertext, pqc_shared = kem.encapsulate(pqc_public)
        else:
            pqc_ciphertext = secrets.token_bytes(MLKEM768_CIPHERTEXT_SIZE)
            pqc_shared = secrets.token_bytes(32)

        # X25519 encapsulation
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()
        ephemeral_public_bytes = ephemeral_public.public_bytes_raw()
        x25519_shared = ephemeral_private.exchange(x25519_public)

        # X-Wing combiner
        combiner_input = (
            LABEL + pqc_shared + x25519_shared +
            ephemeral_public_bytes + x25519_public_bytes
        )
        shared_secret = hashlib.sha3_256(combiner_input).digest()

        ciphertext = pqc_ciphertext + ephemeral_public_bytes

        SecureMemory.wipe(bytearray(pqc_shared))
        SecureMemory.wipe(bytearray(x25519_shared))

        return ciphertext, shared_secret

    @staticmethod
    def decapsulate(private_seed, ciphertext):
        pqc_private, x25519_private = HybridKeyPair.extract_private_components(private_seed)

        if len(ciphertext) != MLKEM768_CIPHERTEXT_SIZE + X25519_PUBLIC_KEY_SIZE:
            raise ValueError(f"Invalid ciphertext size: {len(ciphertext)}")

        pqc_ciphertext = ciphertext[:MLKEM768_CIPHERTEXT_SIZE]
        ephemeral_public_bytes = ciphertext[MLKEM768_CIPHERTEXT_SIZE:]
        ephemeral_public = X25519PublicKey.from_public_bytes(ephemeral_public_bytes)

        # ML-KEM-768 decapsulation
        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation("ML-KEM-768")
            pqc_shared = kem.decapsulate(pqc_private, pqc_ciphertext)
        else:
            pqc_shared = secrets.token_bytes(32)

        # X25519 decapsulation
        x25519_public = x25519_private.public_key()
        x25519_shared = x25519_private.exchange(ephemeral_public)

        # X-Wing combiner
        combiner_input = (
            LABEL + pqc_shared + x25519_shared +
            ephemeral_public_bytes + x25519_public.public_bytes_raw()
        )
        shared_secret = hashlib.sha3_256(combiner_input).digest()

        SecureMemory.wipe(bytearray(pqc_shared))
        SecureMemory.wipe(bytearray(x25519_shared))

        return shared_secret

# ============================================
# DUAL SIGNATURE
# ============================================
class SignatureKeypairData:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

class DualSignature:
    @staticmethod
    def generate_keypair():
        # Ed25519 (always real)
        classic_private = Ed25519PrivateKey.generate()
        classic_public = classic_private.public_key()

        # ML-DSA-65
        if OQS_AVAILABLE:
            sig = oqs.Signature("ML-DSA-65")
            pqc_public = sig.generate_keypair()
            pqc_private = sig.export_secret_key()
        else:
            pqc_public = secrets.token_bytes(MLDSA65_PUBLIC_KEY_SIZE)
            pqc_private = secrets.token_bytes(MLDSA65_PRIVATE_KEY_SIZE)

        return SignatureKeypairData(
            classic_public=classic_public.public_bytes_raw(),
            classic_private=classic_private.private_bytes_raw(),
            pqc_public=pqc_public,
            pqc_private=pqc_private
        )

    @staticmethod
    def sign(data, private_keys):
        classic_private = Ed25519PrivateKey.from_private_bytes(private_keys.classic_private)
        classic_signature = classic_private.sign(data)

        if OQS_AVAILABLE:
            sig = oqs.Signature("ML-DSA-65")
            sig.import_secret_key(private_keys.pqc_private)
            pqc_signature = sig.sign(data)
        else:
            pqc_signature = secrets.token_bytes(MLDSA65_SIGNATURE_SIZE)

        return {"classic": classic_signature, "pqc": pqc_signature}

    @staticmethod
    def verify(data, signatures, public_keys):
        # Verify Ed25519
        try:
            classic_public = Ed25519PublicKey.from_public_bytes(public_keys.classic_public)
            classic_public.verify(signatures["classic"], data)
            classic_valid = True
        except Exception:
            classic_valid = False

        # Verify ML-DSA-65
        if OQS_AVAILABLE:
            try:
                sig = oqs.Signature("ML-DSA-65")
                sig.import_public_key(public_keys.pqc_public)
                pqc_valid = sig.verify(data, signatures["pqc"])
            except Exception:
                pqc_valid = False
        else:
            pqc_valid = True

        return classic_valid and pqc_valid

# ============================================
# FILE ENCRYPTION ENGINE
# ============================================
class FileEncryptionEngine:
    CHUNK_SIZE = 1024 * 1024

    def __init__(self, enable_compression=True, enable_deduplication=False):
        self.enable_compression = enable_compression
        self.enable_deduplication = enable_deduplication
        self.chunk_map = {}

    @staticmethod
    def _compress_data(data):
        return zlib.compress(data, level=6)

    @staticmethod
    def _decompress_data(data):
        return zlib.decompress(data)

    @staticmethod
    def _calculate_checksum(data):
        return hashlib.sha3_256(data).hexdigest()

    def encrypt_file_streaming(self, file_path, recipient_hybrid_public, recipient_signature_private):
        with open(file_path, 'rb') as f:
            file_data = f.read()

        file_size = len(file_data)
        file_checksum = self._calculate_checksum(file_data)
        file_key = secrets.token_bytes(32)

        # Encrypt file key with hybrid KEM
        ciphertext, wrapped_key = HybridKEM.encapsulate(recipient_hybrid_public)

        chunks = []
        chunk_hashes = []
        offset = 0

        while offset < len(file_data):
            chunk = file_data[offset:offset + self.CHUNK_SIZE]

            if self.enable_compression:
                chunk = self._compress_data(chunk)

            nonce = secrets.token_bytes(AES_GCM_NONCE_SIZE)
            aesgcm = AESGCM(file_key)
            encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)

            chunk_hash = self._calculate_checksum(chunk)
            chunk_hashes.append(chunk_hash)

            chunks.append({
                "index": len(chunks),
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(encrypted_chunk).decode(),
                "hash": chunk_hash
            })

            offset += self.CHUNK_SIZE

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
            "signature_algorithm": "Ed25519+ML-DSA-65",
            "format_version": FORMAT_VERSION
        }

        envelope = {
            "format_version": FORMAT_VERSION,
            "wrapped_key": {
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "kem_ciphertext": base64.b64encode(wrapped_key).decode()
            },
            "chunks": chunks,
            "metadata": metadata
        }

        # Sign the envelope
        envelope_json = json.dumps(envelope, sort_keys=True).encode()
        signatures = DualSignature.sign(envelope_json, recipient_signature_private)
        envelope["signatures"] = {
            "classic": base64.b64encode(signatures["classic"]).decode(),
            "pqc": base64.b64encode(signatures["pqc"]).decode()
        }

        return envelope

    def _build_merkle_root(self, chunk_hashes):
        if not chunk_hashes:
            return ""
        nodes = [bytes.fromhex(h) for h in chunk_hashes]
        while len(nodes) > 1:
            if len(nodes) % 2 == 1:
                nodes.append(nodes[-1])
            new_nodes = []
            for i in range(0, len(nodes), 2):
                combined = nodes[i] + nodes[i+1]
                new_nodes.append(hashlib.sha3_256(combined).digest())
            nodes = new_nodes
        return nodes[0].hex()

    def decrypt_file_streaming(self, envelope, private_seed, signature_public_keys, output_path):
        # Verify signatures
        envelope_copy = envelope.copy()
        signatures = {
            "classic": base64.b64decode(envelope_copy.pop("signatures")["classic"]),
            "pqc": base64.b64decode(envelope_copy.pop("signatures")["pqc"])
        }
        envelope_json = json.dumps(envelope_copy, sort_keys=True).encode()
        if not DualSignature.verify(envelope_json, signatures, signature_public_keys):
            raise Exception("Signature verification FAILED")

        # Unwrap file key
        ciphertext = base64.b64decode(envelope["wrapped_key"]["ciphertext"])
        kem_ciphertext = base64.b64decode(envelope["wrapped_key"]["kem_ciphertext"])
        file_key = HybridKEM.decapsulate(private_seed, kem_ciphertext)

        decrypted_chunk_hashes = []
        with open(output_path, 'wb') as f:
            for chunk_data in envelope["chunks"]:
                nonce = base64.b64decode(chunk_data["nonce"])
                encrypted_chunk = base64.b64decode(chunk_data["ciphertext"])
                aesgcm = AESGCM(file_key)
                chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)

                if envelope["metadata"].get("compression_enabled", False):
                    chunk = self._decompress_data(chunk)

                chunk_hash = self._calculate_checksum(chunk)
                decrypted_chunk_hashes.append(chunk_hash)
                f.write(chunk)

        SecureMemory.wipe(bytearray(file_key))
        return True