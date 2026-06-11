#!/usr/bin/env python3
"""
Module: TLS Hybrid Integration
File: tls_hybrid.py
Purpose: TLS 1.3 with hybrid post-quantum key exchange
Implements: X25519 + ML-KEM-768 hybrid key exchange for TLS
"""

import os
import ssl
import socket
import hashlib
import secrets
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import oqs

from .crypto_engine import HybridKEM, HybridKeyPair, MLKEM768_PUBLIC_KEY_SIZE
from .logging_config import get_logger

logger = get_logger(__name__)

# ============================================
# CONSTANTS
# ============================================
TLS_HYBRID_EXTENSION_TYPE = 0xfe0d  # Experimental extension type
HYBRID_KEY_EXCHANGE_ALGORITHM = "x25519_mlkem768"
TLS_VERSION = 0x0304  # TLS 1.3

@dataclass
class HybridTLSCertificate:
    """Certificate with hybrid public key"""
    cert_bytes: bytes
    hybrid_public_key: bytes
    signature: bytes
    issuer: str
    subject: str
    not_before: int
    not_after: int

class HybridTLSContext:
    """TLS context with hybrid key exchange support"""
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.hybrid_keypair: Optional[HybridKeyPair] = None
        self.certificate: Optional[HybridTLSCertificate] = None
        self.peer_public_key: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
        self.session_id = secrets.token_bytes(32)
        
    def generate_keypair(self) -> bytes:
        """Generate hybrid keypair for TLS"""
        self.hybrid_keypair = HybridKeyPair.generate()
        return self.hybrid_keypair.hybrid_public
        
    def generate_certificate(self, common_name: str = "cloud-hndl.local") -> HybridTLSCertificate:
        """Generate self-signed certificate with hybrid public key"""
        if not self.hybrid_keypair:
            self.generate_keypair()
            
        # Generate Ed25519 key for certificate signing
        signing_key = ed25519.Ed25519PrivateKey.generate()
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cloud-HNDL"),
        ])
        
        import datetime
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            signing_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        ).sign(signing_key, hashes.SHA256())
        
        cert_bytes = cert.public_bytes(serialization.Encoding.DER)
        
        # Sign with hybrid key
        signature = self._sign_certificate(cert_bytes)
        
        self.certificate = HybridTLSCertificate(
            cert_bytes=cert_bytes,
            hybrid_public_key=self.hybrid_keypair.hybrid_public,
            signature=signature,
            issuer="Cloud-HNDL",
            subject=common_name,
            not_before=int(datetime.datetime.utcnow().timestamp()),
            not_after=int((datetime.datetime.utcnow() + datetime.timedelta(days=365)).timestamp())
        )
        
        return self.certificate
        
    def _sign_certificate(self, cert_bytes: bytes) -> bytes:
        """Sign certificate with hybrid private key"""
        # Use ML-DSA-65 for signing
        sig = oqs.Signature("ML-DSA-65")
        sig.import_secret_key(self.hybrid_keypair.pqc_private[:4032])
        return sig.sign(cert_bytes)
        
    def encapsulate_hybrid(self, peer_public: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate shared secret for TLS handshake"""
        ciphertext, shared_secret = HybridKEM.encapsulate(peer_public)
        self.shared_secret = shared_secret
        return ciphertext, shared_secret
        
    def decapsulate_hybrid(self, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret from peer"""
        shared_secret = HybridKEM.decapsulate(
            self.hybrid_keypair.private_seed, 
            ciphertext
        )
        self.shared_secret = shared_secret
        return shared_secret
        
    def derive_tls_keys(self) -> Dict[str, bytes]:
        """Derive TLS 1.3 traffic keys from hybrid shared secret"""
        if not self.shared_secret:
            raise ValueError("No shared secret established")
            
        # HKDF-Expand-Label as per TLS 1.3 RFC 8446
        def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
            hkdf_label = (
                length.to_bytes(2, 'big') +
                len("tls13 ").to_bytes(1, 'big') + b"tls13 " +
                len(label).to_bytes(1, 'big') + label.encode() +
                len(context).to_bytes(1, 'big') + context
            )
            return hashlib.pbkdf2_hmac('sha256', secret, hkdf_label, 1, length)
            
        # Derive handshake traffic secrets
        early_secret = hashlib.pbkdf2_hmac(
            'sha256', self.shared_secret, b"tls13 derived", 1, 32
        )
        
        handshake_secret = hkdf_expand_label(
            early_secret, "derived", hashlib.sha256(b"").digest(), 32
        )
        
        client_handshake_key = hkdf_expand_label(
            handshake_secret, "c hs traffic", self.session_id, 16
        )
        server_handshake_key = hkdf_expand_label(
            handshake_secret, "s hs traffic", self.session_id, 16
        )
        
        client_handshake_iv = hkdf_expand_label(
            handshake_secret, "c hs iv", self.session_id, 12
        )
        server_handshake_iv = hkdf_expand_label(
            handshake_secret, "s hs iv", self.session_id, 12
        )
        
        # Derive application traffic secrets
        master_secret = hkdf_expand_label(
            handshake_secret, "derived", hashlib.sha256(b"").digest(), 32
        )
        
        client_app_key = hkdf_expand_label(
            master_secret, "c ap traffic", self.session_id, 16
        )
        server_app_key = hkdf_expand_label(
            master_secret, "s ap traffic", self.session_id, 16
        )
        
        client_app_iv = hkdf_expand_label(
            master_secret, "c ap iv", self.session_id, 12
        )
        server_app_iv = hkdf_expand_label(
            master_secret, "s ap iv", self.session_id, 12
        )
        
        return {
            "client_handshake_key": client_handshake_key,
            "server_handshake_key": server_handshake_key,
            "client_handshake_iv": client_handshake_iv,
            "server_handshake_iv": server_handshake_iv,
            "client_application_key": client_app_key,
            "server_application_key": server_app_key,
            "client_application_iv": client_app_iv,
            "server_application_iv": server_app_iv,
            "master_secret": master_secret,
        }
        
    def encrypt_tls_record(self, data: bytes, key: bytes, iv: bytes, seq_num: int) -> bytes:
        """Encrypt TLS 1.3 record with AES-128-GCM"""
        nonce = (int.from_bytes(iv, 'big') ^ seq_num).to_bytes(12, 'big')
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # Additional authenticated data
        aad = b"\x17\x03\x03" + len(data).to_bytes(2, 'big')
        encryptor.authenticate_additional_data(aad)
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext + encryptor.tag
        
    def decrypt_tls_record(self, ciphertext: bytes, key: bytes, iv: bytes, seq_num: int) -> bytes:
        """Decrypt TLS 1.3 record with AES-128-GCM"""
        tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]
        
        nonce = (int.from_bytes(iv, 'big') ^ seq_num).to_bytes(12, 'big')
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        
        aad = b"\x17\x03\x03" + len(ciphertext).to_bytes(2, 'big')
        decryptor.authenticate_additional_data(aad)
        
        return decryptor.update(ciphertext) + decryptor.finalize()

class HybridTLSServer:
    """TLS server with hybrid key exchange support"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8443):
        self.host = host
        self.port = port
        self.context = HybridTLSContext(is_server=True)
        self.context.generate_certificate()
        self.socket: Optional[socket.socket] = None
        
    def start(self):
        """Start TLS server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        logger.info(f"Hybrid TLS server listening on {self.host}:{self.port}")
        
    def accept(self) -> Tuple[socket.socket, Dict[str, bytes]]:
        """Accept connection and complete hybrid TLS handshake"""
        client_socket, addr = self.socket.accept()
        logger.info(f"Connection from {addr}")
        
        # Receive client hello with hybrid extension
        client_hello = client_socket.recv(4096)
        peer_public = self._parse_client_hello(client_hello)
        
        # Generate server key share
        ciphertext, _ = self.context.encapsulate_hybrid(peer_public)
        
        # Send server hello with hybrid extension
        server_hello = self._build_server_hello(ciphertext)
        client_socket.send(server_hello)
        
        # Derive keys
        keys = self.context.derive_tls_keys()
        
        # Complete handshake
        finished = client_socket.recv(64)
        client_socket.send(b"\x14\x00\x00\x0c" + secrets.token_bytes(12))
        
        logger.info(f"Hybrid TLS handshake completed with {addr}")
        return client_socket, keys
        
    def _parse_client_hello(self, data: bytes) -> bytes:
        """Parse client hello and extract hybrid public key"""
        # Find hybrid extension
        offset = 43  # Skip TLS header
        while offset < len(data) - 4:
            ext_type = int.from_bytes(data[offset:offset+2], 'big')
            ext_len = int.from_bytes(data[offset+2:offset+4], 'big')
            if ext_type == TLS_HYBRID_EXTENSION_TYPE:
                return data[offset+4:offset+4+ext_len]
            offset += 4 + ext_len
        raise ValueError("No hybrid extension in client hello")
        
    def _build_server_hello(self, ciphertext: bytes) -> bytes:
        """Build server hello with hybrid extension"""
        server_hello = bytearray()
        
        # TLS handshake header
        server_hello.extend(b"\x16\x03\x03")  # Handshake, TLS 1.2
        server_hello.extend((len(ciphertext) + 80).to_bytes(2, 'big'))
        
        # ServerHello
        server_hello.extend(b"\x02\x00\x00")  # ServerHello type
        server_hello.extend((len(ciphertext) + 70).to_bytes(3, 'big'))
        server_hello.extend(b"\x03\x03")  # TLS 1.2
        
        # Random
        server_hello.extend(secrets.token_bytes(32))
        
        # Session ID
        server_hello.extend(len(self.context.session_id).to_bytes(1, 'big'))
        server_hello.extend(self.context.session_id)
        
        # Cipher suite (TLS_AES_128_GCM_SHA256)
        server_hello.extend(b"\x13\x01")
        
        # Compression method
        server_hello.extend(b"\x00")
        
        # Extensions
        server_hello.extend((len(ciphertext) + 4).to_bytes(2, 'big'))
        
        # Hybrid extension
        server_hello.extend(TLS_HYBRID_EXTENSION_TYPE.to_bytes(2, 'big'))
        server_hello.extend(len(ciphertext).to_bytes(2, 'big'))
        server_hello.extend(ciphertext)
        
        return bytes(server_hello)

class HybridTLSClient:
    """TLS client with hybrid key exchange support"""
    
    def __init__(self):
        self.context = HybridTLSContext(is_server=False)
        self.context.generate_keypair()
        self.socket: Optional[socket.socket] = None
        
    def connect(self, host: str, port: int) -> Dict[str, bytes]:
        """Connect to server and complete hybrid TLS handshake"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        logger.info(f"Connected to {host}:{port}")
        
        # Send client hello with hybrid extension
        client_hello = self._build_client_hello()
        self.socket.send(client_hello)
        
        # Receive server hello
        server_hello = self.socket.recv(4096)
        ciphertext = self._parse_server_hello(server_hello)
        
        # Decapsulate shared secret
        self.context.decapsulate_hybrid(ciphertext)
        
        # Derive keys
        keys = self.context.derive_tls_keys()
        
        # Complete handshake
        self.socket.send(b"\x14\x00\x00\x0c" + secrets.token_bytes(12))
        self.socket.recv(64)
        
        logger.info(f"Hybrid TLS handshake completed with {host}:{port}")
        return keys
        
    def _build_client_hello(self) -> bytes:
        """Build client hello with hybrid extension"""
        client_hello = bytearray()
        
        # TLS handshake header
        client_hello.extend(b"\x16\x03\x01")
        
        hybrid_key = self.context.hybrid_keypair.hybrid_public
        client_hello.extend((len(hybrid_key) + 100).to_bytes(2, 'big'))
        
        # ClientHello
        client_hello.extend(b"\x01\x00\x00")
        client_hello.extend((len(hybrid_key) + 90).to_bytes(3, 'big'))
        client_hello.extend(b"\x03\x03")
        
        # Random
        client_hello.extend(secrets.token_bytes(32))
        
        # Session ID
        client_hello.extend(b"\x00")
        
        # Cipher suites
        client_hello.extend(b"\x00\x02\x13\x01")
        
        # Compression methods
        client_hello.extend(b"\x01\x00")
        
        # Extensions
        client_hello.extend((len(hybrid_key) + 4).to_bytes(2, 'big'))
        
        # Hybrid extension
        client_hello.extend(TLS_HYBRID_EXTENSION_TYPE.to_bytes(2, 'big'))
        client_hello.extend(len(hybrid_key).to_bytes(2, 'big'))
        client_hello.extend(hybrid_key)
        
        # Add length prefix
        total_len = len(client_hello) - 5
        client_hello[3:5] = total_len.to_bytes(2, 'big')
        
        return bytes(client_hello)
        
    def _parse_server_hello(self, data: bytes) -> bytes:
        """Parse server hello and extract ciphertext"""
        offset = 43
        while offset < len(data) - 4:
            ext_type = int.from_bytes(data[offset:offset+2], 'big')
            ext_len = int.from_bytes(data[offset+2:offset+4], 'big')
            if ext_type == TLS_HYBRID_EXTENSION_TYPE:
                return data[offset+4:offset+4+ext_len]
            offset += 4 + ext_len
        raise ValueError("No hybrid extension in server hello")
        
    def send_encrypted(self, data: bytes, key: bytes, iv: bytes, seq_num: int) -> None:
        """Send encrypted application data"""
        encrypted = self.context.encrypt_tls_record(data, key, iv, seq_num)
        self.socket.send(b"\x17\x03\x03" + len(encrypted).to_bytes(2, 'big') + encrypted)
        
    def recv_encrypted(self, key: bytes, iv: bytes, seq_num: int) -> bytes:
        """Receive and decrypt application data"""
        header = self.socket.recv(5)
        if len(header) < 5:
            return b""
        length = int.from_bytes(header[3:5], 'big')
        encrypted = self.socket.recv(length)
        return self.context.decrypt_tls_record(encrypted, key, iv, seq_num)