#!/usr/bin/env python3
"""
Module: mTLS with Post-Quantum Certificates
File: mtls_pqc.py
Purpose: Mutual TLS with hybrid post-quantum certificates
Implements: X.509 certificates with hybrid public keys, mTLS handshake
"""

import os
import ssl
import socket
import hashlib
import secrets
from typing import Tuple, Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import oqs

from .crypto_engine import HybridKeyPair, DualSignature, SignatureKeypairData
from .tls_hybrid import HybridTLSContext, HybridTLSCertificate
from .logging_config import get_logger

logger = get_logger(__name__)

# ============================================
# HYBRID X.509 CERTIFICATE
# ============================================

@dataclass
class HybridX509Certificate:
    """X.509 certificate with hybrid post-quantum public key"""
    serial_number: int
    issuer: str
    subject: str
    not_before: datetime
    not_after: datetime
    hybrid_public_key: bytes
    signature_algorithm: str
    signature: bytes
    extensions: Dict[str, Any] = field(default_factory=dict)
    issuer_cert: Optional["HybridX509Certificate"] = None
    
    def to_pem(self) -> str:
        """Convert certificate to PEM format"""
        import base64
        lines = ["-----BEGIN CERTIFICATE-----"]
        der_data = self._to_der()
        b64 = base64.b64encode(der_data).decode('ascii')
        for i in range(0, len(b64), 64):
            lines.append(b64[i:i+64])
        lines.append("-----END CERTIFICATE-----")
        return '\n'.join(lines)
    
    def _to_der(self) -> bytes:
        """Serialize to DER format"""
        import struct
        data = bytearray()
        
        # Version
        data.extend(b'\x30\x03\x02\x01\x02')  # v3
        
        # Serial number
        data.extend(self._encode_integer(self.serial_number))
        
        # Signature algorithm
        data.extend(self._encode_oid("1.3.6.1.4.1.54392.1.1"))  # Hybrid signature
        
        # Issuer
        issuer_bytes = self._encode_name(self.issuer)
        data.extend(issuer_bytes)
        
        # Validity
        validity = self._encode_validity(self.not_before, self.not_after)
        data.extend(validity)
        
        # Subject
        subject_bytes = self._encode_name(self.subject)
        data.extend(subject_bytes)
        
        # Subject public key info
        spki = self._encode_spki(self.hybrid_public_key)
        data.extend(spki)
        
        # Extensions
        if self.extensions:
            ext_data = self._encode_extensions(self.extensions)
            data.extend(b'\xa3' + len(ext_data).to_bytes(1, 'big') + ext_data)
        
        # Wrap in SEQUENCE
        return b'\x30' + len(data).to_bytes(2, 'big') + data
    
    def _encode_integer(self, value: int) -> bytes:
        """Encode ASN.1 INTEGER"""
        if value == 0:
            return b'\x02\x01\x00'
        hex_val = hex(value)[2:]
        if len(hex_val) % 2:
            hex_val = '0' + hex_val
        val_bytes = bytes.fromhex(hex_val)
        if val_bytes[0] & 0x80:
            val_bytes = b'\x00' + val_bytes
        return b'\x02' + len(val_bytes).to_bytes(1, 'big') + val_bytes
    
    def _encode_oid(self, oid: str) -> bytes:
        """Encode ASN.1 OID"""
        parts = [int(p) for p in oid.split('.')]
        encoded = bytes([40 * parts[0] + parts[1]])
        for p in parts[2:]:
            if p < 128:
                encoded += bytes([p])
            else:
                encoded += bytes([0x80 | (p >> 7), p & 0x7F])
        return b'\x06' + len(encoded).to_bytes(1, 'big') + encoded
    
    def _encode_name(self, name: str) -> bytes:
        """Encode X.509 Name"""
        cn_bytes = name.encode('utf-8')
        rdn = (
            b'\x31' + len(cn_bytes).to_bytes(1, 'big') +
            b'\x30' + (len(cn_bytes) + 4).to_bytes(1, 'big') +
            b'\x06\x03\x55\x04\x03' +  # CN OID
            b'\x0c' + len(cn_bytes).to_bytes(1, 'big') + cn_bytes
        )
        return b'\x30' + len(rdn).to_bytes(1, 'big') + rdn
    
    def _encode_validity(self, not_before: datetime, not_after: datetime) -> bytes:
        """Encode certificate validity period"""
        def format_time(dt: datetime) -> bytes:
            return dt.strftime("%y%m%d%H%M%SZ").encode('ascii')
        
        nb = b'\x17\x0d' + format_time(not_before)
        na = b'\x17\x0d' + format_time(not_after)
        return b'\x30' + (len(nb) + len(na)).to_bytes(1, 'big') + nb + na
    
    def _encode_spki(self, public_key: bytes) -> bytes:
        """Encode SubjectPublicKeyInfo"""
        algo_id = (
            b'\x30\x0d' +
            b'\x06\x0b' + self._encode_oid("1.3.6.1.4.1.54392.1.2")[2:]  # Hybrid KEM
        )
        key_data = b'\x03' + (len(public_key) + 1).to_bytes(1, 'big') + b'\x00' + public_key
        return b'\x30' + (len(algo_id) + len(key_data)).to_bytes(1, 'big') + algo_id + key_data
    
    def _encode_extensions(self, extensions: Dict[str, Any]) -> bytes:
        """Encode X.509 extensions"""
        ext_list = bytearray()
        
        for oid, value in extensions.items():
            if oid == "subjectAltName":
                san_bytes = self._encode_san(value)
                ext = (
                    b'\x30' + len(san_bytes).to_bytes(1, 'big') +
                    self._encode_oid(oid) +
                    b'\x01\x01\xff' +  # critical
                    b'\x04' + len(san_bytes).to_bytes(1, 'big') + san_bytes
                )
                ext_list.extend(ext)
            elif oid == "keyUsage":
                ku_bytes = self._encode_key_usage(value)
                ext = (
                    b'\x30' + len(ku_bytes).to_bytes(1, 'big') +
                    self._encode_oid(oid) +
                    b'\x01\x01\xff' +
                    b'\x04' + len(ku_bytes).to_bytes(1, 'big') + ku_bytes
                )
                ext_list.extend(ext)
        
        return bytes(ext_list)
    
    def _encode_san(self, dns_names: List[str]) -> bytes:
        """Encode SubjectAlternativeName"""
        san_data = bytearray()
        for name in dns_names:
            name_bytes = name.encode('utf-8')
            san_data.extend(b'\x82' + len(name_bytes).to_bytes(1, 'big') + name_bytes)
        return b'\x30' + len(san_data).to_bytes(1, 'big') + san_data
    
    def _encode_key_usage(self, usage: List[str]) -> bytes:
        """Encode KeyUsage"""
        ku_map = {
            "digitalSignature": 0,
            "nonRepudiation": 1,
            "keyEncipherment": 2,
            "dataEncipherment": 3,
            "keyAgreement": 4,
            "keyCertSign": 5,
            "cRLSign": 6,
        }
        bits = 0
        for u in usage:
            if u in ku_map:
                bits |= (1 << (7 - ku_map[u]))
        return b'\x03\x02\x07' + bits.to_bytes(1, 'big')

# ============================================
# CERTIFICATE AUTHORITY
# ============================================

class HybridCertificateAuthority:
    """Certificate Authority for hybrid post-quantum certificates"""
    
    def __init__(self, common_name: str = "Cloud-HNDL Root CA"):
        self.common_name = common_name
        self.root_keypair: Optional[HybridKeyPair] = None
        self.root_cert: Optional[HybridX509Certificate] = None
        self.signature_keys: Optional[SignatureKeypairData] = None
        self.serial_counter = 1
        self.issued_certificates: Dict[str, HybridX509Certificate] = {}
        self.revoked_certificates: Dict[str, datetime] = {}
        
    def initialize(self) -> HybridX509Certificate:
        """Initialize CA with root certificate"""
        logger.info(f"Initializing CA: {self.common_name}")
        
        # Generate root keypair
        self.root_keypair = HybridKeyPair.generate()
        
        # Generate signature keys for certificates
        self.signature_keys = DualSignature.generate_keypair()
        
        # Create self-signed root certificate
        self.root_cert = self._create_certificate(
            subject=self.common_name,
            issuer=self.common_name,
            public_key=self.root_keypair.hybrid_public,
            is_ca=True,
        )
        
        # Self-sign
        self.root_cert.signature = self._sign_certificate(self.root_cert)
        
        logger.info(f"CA initialized with serial {self.root_cert.serial_number}")
        return self.root_cert
    
    def _create_certificate(
        self,
        subject: str,
        issuer: str,
        public_key: bytes,
        is_ca: bool = False,
        valid_days: int = 365,
        dns_names: List[str] = None,
    ) -> HybridX509Certificate:
        """Create a new certificate"""
        cert = HybridX509Certificate(
            serial_number=self.serial_counter,
            issuer=issuer,
            subject=subject,
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=valid_days),
            hybrid_public_key=public_key,
            signature_algorithm="ML-DSA-65+Ed25519",
            signature=b"",
            extensions={},
        )
        
        if dns_names:
            cert.extensions["subjectAltName"] = dns_names
        
        if is_ca:
            cert.extensions["keyUsage"] = ["keyCertSign", "cRLSign"]
            cert.extensions["basicConstraints"] = {"ca": True}
        else:
            cert.extensions["keyUsage"] = ["digitalSignature", "keyEncipherment"]
            cert.extensions["basicConstraints"] = {"ca": False}
        
        self.serial_counter += 1
        return cert
    
    def _sign_certificate(self, cert: HybridX509Certificate) -> bytes:
        """Sign certificate with CA's signature keys"""
        tbs_data = cert._to_der()
        signatures = DualSignature.sign(tbs_data, self.signature_keys)
        return signatures["classic"] + signatures["pqc"]
    
    def issue_certificate(
        self,
        subject: str,
        public_key: bytes,
        dns_names: List[str] = None,
        valid_days: int = 365,
    ) -> HybridX509Certificate:
        """Issue a new certificate"""
        logger.info(f"Issuing certificate for {subject}")
        
        cert = self._create_certificate(
            subject=subject,
            issuer=self.common_name,
            public_key=public_key,
            is_ca=False,
            valid_days=valid_days,
            dns_names=dns_names,
        )
        
        cert.signature = self._sign_certificate(cert)
        cert.issuer_cert = self.root_cert
        
        self.issued_certificates[subject] = cert
        return cert
    
    def verify_certificate(self, cert: HybridX509Certificate) -> bool:
        """Verify a certificate's signature"""
        if cert.issuer != self.common_name:
            logger.warning(f"Certificate issued by unknown CA: {cert.issuer}")
            return False
        
        if datetime.utcnow() > cert.not_after:
            logger.warning(f"Certificate expired: {cert.subject}")
            return False
        
        if cert.serial_number in self.revoked_certificates:
            logger.warning(f"Certificate revoked: {cert.subject}")
            return False
        
        tbs_data = cert._to_der()
        signature = cert.signature
        
        # Split combined signature
        classic_sig = signature[:64]
        pqc_sig = signature[64:]
        
        verify_keys = SignatureKeypairData(
            classic_public=self.signature_keys.classic_public,
            classic_private=b"",
            pqc_public=self.signature_keys.pqc_public,
            pqc_private=b"",
        )
        
        return DualSignature.verify(
            tbs_data,
            {"classic": classic_sig, "pqc": pqc_sig},
            verify_keys
        )
    
    def revoke_certificate(self, serial_number: int, reason: str = "unspecified"):
        """Revoke a certificate"""
        self.revoked_certificates[serial_number] = datetime.utcnow()
        logger.info(f"Revoked certificate {serial_number}: {reason}")
    
    def generate_crl(self) -> bytes:
        """Generate Certificate Revocation List"""
        crl_data = bytearray()
        
        # CRL header
        crl_data.extend(b'\x30\x82')  # SEQUENCE
        
        # Issuer
        issuer_bytes = self.root_cert._encode_name(self.common_name)
        crl_data.extend(issuer_bytes)
        
        # This update
        now = datetime.utcnow()
        crl_data.extend(b'\x17\x0d' + now.strftime("%y%m%d%H%M%SZ").encode())
        
        # Next update
        next_update = now + timedelta(days=7)
        crl_data.extend(b'\x17\x0d' + next_update.strftime("%y%m%d%H%M%SZ").encode())
        
        # Revoked certificates
        if self.revoked_certificates:
            revoked_list = bytearray()
            for serial, rev_date in self.revoked_certificates.items():
                revoked_list.extend(
                    b'\x30' + 
                    self.root_cert._encode_integer(serial) +
                    b'\x17\x0d' + rev_date.strftime("%y%m%d%H%M%SZ").encode()
                )
            crl_data.extend(b'\x30' + len(revoked_list).to_bytes(1, 'big') + revoked_list)
        
        return bytes(crl_data)

# ============================================
# mTLS SERVER
# ============================================

class HybridMTLSServer:
    """mTLS server with hybrid post-quantum certificates"""
    
    def __init__(self, ca: HybridCertificateAuthority, server_cert: HybridX509Certificate):
        self.ca = ca
        self.server_cert = server_cert
        self.server_keypair: Optional[HybridKeyPair] = None
        self.context = HybridTLSContext(is_server=True)
        self.socket: Optional[socket.socket] = None
        
    def initialize(self, host: str = "0.0.0.0", port: int = 8443):
        """Initialize mTLS server"""
        self.server_keypair = HybridKeyPair.generate()
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.socket.listen(5)
        
        logger.info(f"Hybrid mTLS server listening on {host}:{port}")
        
    def accept(self) -> Tuple[socket.socket, HybridX509Certificate, Dict[str, bytes]]:
        """Accept mTLS connection with client certificate verification"""
        client_socket, addr = self.socket.accept()
        logger.info(f"Connection from {addr}")
        
        # Receive client hello
        client_hello = client_socket.recv(4096)
        client_public, client_cert = self._parse_client_hello(client_hello)
        
        # Verify client certificate
        if not self.ca.verify_certificate(client_cert):
            client_socket.close()
            raise Exception("Client certificate verification failed")
        
        logger.info(f"Client {client_cert.subject} authenticated")
        
        # Complete hybrid handshake
        ciphertext, keys = self.context.encapsulate_hybrid(client_public)
        
        # Send server hello with server certificate
        server_hello = self._build_server_hello(ciphertext, self.server_cert)
        client_socket.send(server_hello)
        
        # Derive session keys
        session_keys = self.context.derive_tls_keys()
        
        return client_socket, client_cert, session_keys
    
    def _parse_client_hello(self, data: bytes) -> Tuple[bytes, HybridX509Certificate]:
        """Parse client hello and extract public key and certificate"""
        # Find certificate in handshake
        offset = 43
        client_public = None
        client_cert = None
        
        while offset < len(data) - 4:
            ext_type = int.from_bytes(data[offset:offset+2], 'big')
            ext_len = int.from_bytes(data[offset+2:offset+4], 'big')
            
            if ext_type == 0xfe0d:  # Hybrid extension
                client_public = data[offset+4:offset+4+ext_len]
            elif ext_type == 0x000b:  # Certificate extension
                # Parse certificate (simplified)
                cert_len = int.from_bytes(data[offset+6:offset+8], 'big')
                cert_der = data[offset+8:offset+8+cert_len]
                client_cert = self._parse_certificate_der(cert_der)
            
            offset += 4 + ext_len
        
        if not client_public or not client_cert:
            raise ValueError("Missing hybrid extension or certificate")
        
        return client_public, client_cert
    
    def _parse_certificate_der(self, der_data: bytes) -> HybridX509Certificate:
        """Parse DER-encoded certificate"""
        # Simplified parsing - in production use proper ASN.1 parser
        # Extract subject from DER
        subject_start = der_data.find(b'\x55\x04\x03')  # CN OID
        if subject_start > 0:
            subject_len = der_data[subject_start + 5]
            subject = der_data[subject_start + 6:subject_start + 6 + subject_len].decode()
        else:
            subject = "unknown"
        
        return HybridX509Certificate(
            serial_number=1,
            issuer=self.ca.common_name,
            subject=subject,
            not_before=datetime.utcnow(),
            not_after=datetime.utcnow() + timedelta(days=365),
            hybrid_public_key=b"",
            signature_algorithm="",
            signature=b"",
        )
    
    def _build_server_hello(self, ciphertext: bytes, cert: HybridX509Certificate) -> bytes:
        """Build server hello with certificate"""
        server_hello = bytearray()
        
        cert_der = cert._to_der()
        
        # TLS handshake header
        server_hello.extend(b"\x16\x03\x03")
        total_len = len(ciphertext) + len(cert_der) + 80
        server_hello.extend(total_len.to_bytes(2, 'big'))
        
        # ServerHello
        server_hello.extend(b"\x02\x00\x00")
        server_hello.extend((len(ciphertext) + 70).to_bytes(3, 'big'))
        server_hello.extend(b"\x03\x03")
        server_hello.extend(secrets.token_bytes(32))
        server_hello.extend(b"\x00")
        server_hello.extend(b"\x13\x01")
        server_hello.extend(b"\x00")
        
        # Certificate message
        server_hello.extend(b"\x0b\x00")
        server_hello.extend((len(cert_der) + 10).to_bytes(2, 'big'))
        server_hello.extend((len(cert_der) + 7).to_bytes(3, 'big'))
        server_hello.extend(len(cert_der).to_bytes(3, 'big'))
        server_hello.extend(cert_der)
        
        # Hybrid extension
        server_hello.extend(TLS_HYBRID_EXTENSION_TYPE.to_bytes(2, 'big'))
        server_hello.extend(len(ciphertext).to_bytes(2, 'big'))
        server_hello.extend(ciphertext)
        
        return bytes(server_hello)

# ============================================
# mTLS CLIENT
# ============================================

class HybridMTLSClient:
    """mTLS client with hybrid post-quantum certificates"""
    
    def __init__(self, client_cert: HybridX509Certificate, client_keypair: HybridKeyPair):
        self.client_cert = client_cert
        self.client_keypair = client_keypair
        self.context = HybridTLSContext(is_server=False)
        self.socket: Optional[socket.socket] = None
        
    def connect(self, host: str, port: int) -> Dict[str, bytes]:
        """Connect to mTLS server with client certificate"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        logger.info(f"Connected to {host}:{port}")
        
        # Send client hello with certificate
        client_hello = self._build_client_hello()
        self.socket.send(client_hello)
        
        # Receive server hello
        server_hello = self.socket.recv(4096)
        ciphertext = self._parse_server_hello(server_hello)
        
        # Decapsulate
        self.context.decapsulate_hybrid(ciphertext)
        
        # Derive session keys
        keys = self.context.derive_tls_keys()
        
        logger.info(f"mTLS handshake completed with {host}:{port}")
        return keys
    
    def _build_client_hello(self) -> bytes:
        """Build client hello with certificate"""
        client_hello = bytearray()
        
        cert_der = self.client_cert._to_der()
        hybrid_key = self.client_keypair.hybrid_public
        
        client_hello.extend(b"\x16\x03\x01")
        total_len = len(hybrid_key) + len(cert_der) + 100
        client_hello.extend(total_len.to_bytes(2, 'big'))
        
        client_hello.extend(b"\x01\x00\x00")
        client_hello.extend((len(hybrid_key) + 90).to_bytes(3, 'big'))
        client_hello.extend(b"\x03\x03")
        client_hello.extend(secrets.token_bytes(32))
        client_hello.extend(b"\x00")
        client_hello.extend(b"\x00\x02\x13\x01")
        client_hello.extend(b"\x01\x00")
        
        # Certificate
        client_hello.extend(b"\x0b\x00")
        client_hello.extend((len(cert_der) + 4).to_bytes(2, 'big'))
        client_hello.extend(len(cert_der).to_bytes(3, 'big'))
        client_hello.extend(cert_der)
        
        # Hybrid extension
        client_hello.extend(TLS_HYBRID_EXTENSION_TYPE.to_bytes(2, 'big'))
        client_hello.extend(len(hybrid_key).to_bytes(2, 'big'))
        client_hello.extend(hybrid_key)
        
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

# TLS extension constant (shared with tls_hybrid.py)
TLS_HYBRID_EXTENSION_TYPE = 0xfe0d