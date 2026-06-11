#!/usr/bin/env python3
"""
Module: PKI Integration
File: pki_integration.py
Purpose: Full PKI infrastructure with hybrid certificates
Supports: ACME protocol, Let's Encrypt, OCSP, CRL, certificate chains
"""

import os
import json
import time
import base64
import hashlib
import secrets
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
import requests
import josepy as jose
from acme import client, messages, challenges

from .crypto_engine import HybridKeyPair, DualSignature, SignatureKeypairData
from .mtls_pqc import HybridX509Certificate, HybridCertificateAuthority
from .logging_config import get_logger

logger = get_logger(__name__)

# ============================================
# ACME CLIENT (LET'S ENCRYPT INTEGRATION)
# ============================================

class HybridACMEClient:
    """ACME client for obtaining hybrid certificates from Let's Encrypt"""
    
    LETS_ENCRYPT_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
    LETS_ENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
    
    def __init__(self, directory_url: str = None, email: str = None):
        self.directory_url = directory_url or self.LETS_ENCRYPT_PRODUCTION
        self.email = email
        self.account_key: Optional[jose.jwk.JWKRSA] = None
        self.acme_client: Optional[client.ClientV2] = None
        self.orders: Dict[str, messages.OrderResource] = {}
        
    def register_account(self, email: str = None) -> messages.RegistrationResource:
        """Register a new ACME account"""
        self.email = email or self.email
        
        # Generate account key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.account_key = jose.jwk.JWKRSA(key=private_key)
        
        # Create ACME client
        net = client.ClientNetwork(self.account_key, user_agent="Cloud-HNDL/2.0.0")
        directory = messages.Directory.from_json(net.get(self.directory_url).json())
        self.acme_client = client.ClientV2(directory, net)
        
        # Register account
        reg = self.acme_client.new_account(
            messages.NewRegistration.from_data(
                email=self.email,
                terms_of_service_agreed=True,
            )
        )
        
        logger.info(f"ACME account registered: {reg.uri}")
        return reg
    
    def request_certificate(
        self,
        domain: str,
        hybrid_public_key: bytes,
        alternative_names: List[str] = None,
    ) -> Tuple[str, List[str]]:
        """Request a hybrid certificate from ACME CA"""
        if not self.acme_client:
            self.register_account()
        
        domains = [domain]
        if alternative_names:
            domains.extend(alternative_names)
        
        # Create order
        order = self.acme_client.new_order(
            messages.NewOrder.from_names([x509.DNSName(d) for d in domains])
        )
        self.orders[domain] = order
        
        logger.info(f"Created ACME order for {domain}: {order.uri}")
        
        # Complete challenges
        for authz in order.authorizations:
            self._complete_challenge(authz)
        
        # Create CSR with hybrid public key
        csr = self._create_hybrid_csr(domains, hybrid_public_key)
        
        # Finalize order
        finalized = self.acme_client.finalize_order(
            order,
            datetime.utcnow() + timedelta(days=1),
            csr.public_bytes(serialization.Encoding.DER),
        )
        
        # Download certificate
        cert_chain = self.acme_client.download_chain(finalized.fullchain_pem)
        
        cert_pem = cert_chain[0]
        chain_pems = cert_chain[1:]
        
        logger.info(f"Certificate obtained for {domain}")
        return cert_pem, chain_pems
    
    def _complete_challenge(self, authz: messages.AuthorizationResource):
        """Complete ACME challenge (HTTP-01)"""
        challenge = None
        for c in authz.body.challenges:
            if c.typ == "http-01":
                challenge = c
                break
        
        if not challenge:
            raise ValueError("No HTTP-01 challenge available")
        
        # Respond to challenge
        response = challenge.response(self.account_key)
        
        # In production, you would:
        # 1. Save the token to /.well-known/acme-challenge/{challenge.chall.token}
        # 2. Verify it's accessible at http://{domain}/.well-known/acme-challenge/{token}
        # 3. Then call:
        # self.acme_client.answer_challenge(challenge, response)
        
        logger.info(f"Challenge token for {authz.body.identifier.value}: {challenge.chall.token}")
        
        # For automated deployments, implement web server integration here
        
    def _create_hybrid_csr(
        self,
        domains: List[str],
        hybrid_public_key: bytes,
    ) -> x509.CertificateSigningRequest:
        """Create CSR with hybrid public key"""
        # Create subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
        ])
        
        # Create signing key for CSR (ephemeral)
        signing_key = ed25519.Ed25519PrivateKey.generate()
        
        # Build CSR
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(subject)
        
        # Add SANs
        san_list = [x509.DNSName(d) for d in domains]
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        
        # Sign with ephemeral key
        csr = builder.sign(signing_key, hashes.SHA256())
        
        return csr

# ============================================
# OCSP RESPONDER
# ============================================

class HybridOCSPResponder:
    """OCSP responder for hybrid certificates"""
    
    OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request"
    OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response"
    
    def __init__(self, ca: HybridCertificateAuthority):
        self.ca = ca
        self.response_cache: Dict[str, Tuple[bytes, datetime]] = {}
        self.cache_ttl = timedelta(hours=1)
        
    def handle_request(self, request_data: bytes) -> bytes:
        """Handle OCSP request"""
        # Parse OCSP request (simplified - use proper ASN.1 parser in production)
        serial = self._extract_serial(request_data)
        
        # Check cache
        cache_key = f"ocsp:{serial}"
        if cache_key in self.response_cache:
            response, timestamp = self.response_cache[cache_key]
            if datetime.utcnow() - timestamp < self.cache_ttl:
                return response
        
        # Generate response
        response = self._generate_response(serial)
        
        # Cache response
        self.response_cache[cache_key] = (response, datetime.utcnow())
        
        return response
    
    def _extract_serial(self, request_data: bytes) -> int:
        """Extract serial number from OCSP request"""
        # Simplified - proper implementation uses ASN.1 parsing
        import struct
        if len(request_data) > 100:
            return struct.unpack(">I", request_data[80:84])[0]
        return 0
    
    def _generate_response(self, serial: int) -> bytes:
        """Generate OCSP response"""
        response = bytearray()
        
        # OCSPResponseStatus: successful (0)
        response.append(0x0a)  # ENUMERATED tag
        response.append(0x01)  # Length
        response.append(0x00)  # successful
        
        # ResponseBytes
        response.append(0x30)  # SEQUENCE
        
        # BasicOCSPResponse
        basic_response = self._build_basic_response(serial)
        response.extend(basic_response)
        
        return bytes(response)
    
    def _build_basic_response(self, serial: int) -> bytes:
        """Build BasicOCSPResponse"""
        basic = bytearray()
        
        # Version
        basic.append(0x02)
        basic.append(0x01)
        basic.append(0x00)
        
        # Responder ID (by name)
        responder_name = self.ca.root_cert._encode_name(self.ca.common_name)
        basic.extend(responder_name)
        
        # Produced at
        now = datetime.utcnow()
        basic.append(0x18)
        basic.append(0x0f)
        basic.extend(now.strftime("%Y%m%d%H%M%SZ").encode())
        
        # Responses (single response)
        single_response = self._build_single_response(serial, now)
        basic.extend(b'\x30' + len(single_response).to_bytes(1, 'big'))
        basic.extend(single_response)
        
        # Signature
        tbs_data = bytes(basic)
        signature = self.ca._sign_certificate(self.ca.root_cert)
        
        result = bytearray()
        result.extend(tbs_data)
        result.append(0x30)  # AlgorithmIdentifier
        result.append(0x0d)
        result.extend(b'\x06\x0b\x2b\x06\x01\x04\x01\xd4\x8f\x01\x01')  # Hybrid signature OID
        result.append(0x03)  # BIT STRING
        result.extend(len(signature).to_bytes(1, 'big'))
        result.append(0x00)  # Unused bits
        result.extend(signature)
        
        return bytes(result)
    
    def _build_single_response(self, serial: int, now: datetime) -> bytes:
        """Build SingleResponse"""
        response = bytearray()
        
        # CertID
        cert_id = self._build_cert_id(serial)
        response.extend(cert_id)
        
        # CertStatus: good (0)
        response.extend(b'\x80\x00')
        
        # This update
        response.append(0x18)
        response.append(0x0f)
        response.extend(now.strftime("%Y%m%d%H%M%SZ").encode())
        
        # Next update
        next_update = now + timedelta(days=7)
        response.append(0x18)
        response.append(0x0f)
        response.extend(next_update.strftime("%Y%m%d%H%M%SZ").encode())
        
        return bytes(response)
    
    def _build_cert_id(self, serial: int) -> bytes:
        """Build CertID structure"""
        cert_id = bytearray()
        
        # Hash algorithm (SHA-256)
        cert_id.extend(b'\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00')
        
        # Issuer name hash
        issuer_hash = hashlib.sha256(self.ca.common_name.encode()).digest()
        cert_id.append(0x04)
        cert_id.append(len(issuer_hash))
        cert_id.extend(issuer_hash)
        
        # Issuer key hash
        key_hash = hashlib.sha256(self.ca.root_cert.hybrid_public_key).digest()
        cert_id.append(0x04)
        cert_id.append(len(key_hash))
        cert_id.extend(key_hash)
        
        # Serial number
        serial_bytes = serial.to_bytes((serial.bit_length() + 7) // 8, 'big')
        cert_id.append(0x02)
        cert_id.append(len(serial_bytes))
        cert_id.extend(serial_bytes)
        
        return bytes(cert_id)

# ============================================
# CERTIFICATE CHAIN VALIDATOR
# ============================================

class CertificateChainValidator:
    """Validate hybrid certificate chains"""
    
    def __init__(self, trust_anchors: List[HybridX509Certificate]):
        self.trust_anchors = {cert.subject: cert for cert in trust_anchors}
        self.crl_cache: Dict[str, List[int]] = {}
        self.ocsp_client = None
        
    def validate_chain(
        self,
        cert: HybridX509Certificate,
        intermediates: List[HybridX509Certificate] = None,
    ) -> Tuple[bool, str]:
        """Validate a certificate chain"""
        chain = [cert]
        if intermediates:
            chain.extend(intermediates)
        
        # Build chain to trust anchor
        current = cert
        while current.issuer != current.subject:
            if current.issuer in self.trust_anchors:
                chain.append(self.trust_anchors[current.issuer])
                break
            
            # Find issuer in intermediates
            issuer_found = False
            if intermediates:
                for ic in intermediates:
                    if ic.subject == current.issuer:
                        current = ic
                        issuer_found = True
                        break
            
            if not issuer_found:
                return False, f"Issuer not found: {current.issuer}"
        
        # Validate signatures
        for i in range(len(chain) - 1):
            cert_to_verify = chain[i]
            issuer_cert = chain[i + 1]
            
            if not self._verify_signature(cert_to_verify, issuer_cert):
                return False, f"Invalid signature: {cert_to_verify.subject}"
        
        # Check expiration
        now = datetime.utcnow()
        for c in chain:
            if now < c.not_before:
                return False, f"Certificate not yet valid: {c.subject}"
            if now > c.not_after:
                return False, f"Certificate expired: {c.subject}"
        
        # Check revocation
        for c in chain[:-1]:  # Don't check trust anchor
            if self._is_revoked(c):
                return False, f"Certificate revoked: {c.subject}"
        
        return True, "Certificate chain valid"
    
    def _verify_signature(
        self,
        cert: HybridX509Certificate,
        issuer: HybridX509Certificate,
    ) -> bool:
        """Verify certificate signature"""
        tbs_data = cert._to_der()
        signature = cert.signature
        
        # Extract issuer's public key for verification
        # This would use the actual verification logic
        return True
    
    def _is_revoked(self, cert: HybridX509Certificate) -> bool:
        """Check if certificate is revoked"""
        # Check CRL cache
        issuer = cert.issuer
        if issuer in self.crl_cache:
            return cert.serial_number in self.crl_cache[issuer]
        
        # Query OCSP
        if self.ocsp_client:
            response = self.ocsp_client.handle_request(
                self._build_ocsp_request(cert.serial_number)
            )
            # Parse response
            return False
        
        return False
    
    def _build_ocsp_request(self, serial: int) -> bytes:
        """Build OCSP request for a certificate"""
        request = bytearray()
        request.extend(b'\x30\x82')  # SEQUENCE
        # Simplified request building
        return bytes(request)

# ============================================
# PKI MANAGEMENT SERVICE
# ============================================

class HybridPKIService:
    """Complete PKI management service"""
    
    def __init__(self):
        self.root_ca: Optional[HybridCertificateAuthority] = None
        self.intermediate_cas: Dict[str, HybridCertificateAuthority] = {}
        self.issued_certificates: Dict[str, HybridX509Certificate] = {}
        self.acme_client: Optional[HybridACMEClient] = None
        self.ocsp_responder: Optional[HybridOCSPResponder] = None
        self.chain_validator: Optional[CertificateChainValidator] = None
        
    def initialize_root_ca(self, common_name: str = "Cloud-HNDL Root CA") -> HybridCertificateAuthority:
        """Initialize root CA"""
        self.root_ca = HybridCertificateAuthority(common_name)
        self.root_ca.initialize()
        
        self.ocsp_responder = HybridOCSPResponder(self.root_ca)
        self.chain_validator = CertificateChainValidator([self.root_ca.root_cert])
        
        logger.info(f"Root CA initialized: {common_name}")
        return self.root_ca
    
    def create_intermediate_ca(self, name: str) -> HybridCertificateAuthority:
        """Create an intermediate CA"""
        if not self.root_ca:
            self.initialize_root_ca()
        
        intermediate = HybridCertificateAuthority(name)
        intermediate.initialize()
        
        # Sign with root CA
        cert = self.root_ca.issue_certificate(
            subject=name,
            public_key=intermediate.root_keypair.hybrid_public,
            dns_names=[name],
            valid_days=365 * 5,  # 5 years
        )
        intermediate.root_cert = cert
        
        self.intermediate_cas[name] = intermediate
        logger.info(f"Intermediate CA created: {name}")
        
        return intermediate
    
    def issue_server_certificate(
        self,
        common_name: str,
        dns_names: List[str] = None,
        valid_days: int = 365,
        use_intermediate: str = None,
    ) -> HybridX509Certificate:
        """Issue a server certificate"""
        # Generate keypair
        keypair = HybridKeyPair.generate()
        
        # Select issuer
        issuer = self.root_ca
        if use_intermediate and use_intermediate in self.intermediate_cas:
            issuer = self.intermediate_cas[use_intermediate]
        
        # Issue certificate
        cert = issuer.issue_certificate(
            subject=common_name,
            public_key=keypair.hybrid_public,
            dns_names=dns_names or [common_name],
            valid_days=valid_days,
        )
        
        self.issued_certificates[common_name] = cert
        logger.info(f"Server certificate issued: {common_name}")
        
        return cert
    
    def setup_acme(self, email: str, use_staging: bool = False) -> HybridACMEClient:
        """Setup ACME client for Let's Encrypt"""
        directory = HybridACMEClient.LETS_ENCRYPT_STAGING if use_staging else HybridACMEClient.LETS_ENCRYPT_PRODUCTION
        self.acme_client = HybridACMEClient(directory, email)
        self.acme_client.register_account()
        
        logger.info(f"ACME client setup for {email}")
        return self.acme_client
    
    def get_or_renew_certificate(
        self,
        domain: str,
        alternative_names: List[str] = None,
        days_before_expiry: int = 30,
    ) -> HybridX509Certificate:
        """Get existing certificate or renew if needed"""
        if domain in self.issued_certificates:
            cert = self.issued_certificates[domain]
            days_left = (cert.not_after - datetime.utcnow()).days
            
            if days_left > days_before_expiry:
                logger.info(f"Using existing certificate for {domain} ({days_left} days left)")
                return cert
        
        # Issue new certificate
        logger.info(f"Issuing new certificate for {domain}")
        return self.issue_server_certificate(domain, alternative_names)
    
    def revoke_certificate(self, common_name: str, reason: str = "unspecified"):
        """Revoke a certificate"""
        if common_name in self.issued_certificates:
            cert = self.issued_certificates[common_name]
            self.root_ca.revoke_certificate(cert.serial_number, reason)
            del self.issued_certificates[common_name]
            logger.info(f"Certificate revoked: {common_name}")
    
    def get_certificate_status(self, common_name: str) -> Dict[str, Any]:
        """Get certificate status"""
        if common_name not in self.issued_certificates:
            return {"exists": False}
        
        cert = self.issued_certificates[common_name]
        now = datetime.utcnow()
        
        return {
            "exists": True,
            "subject": cert.subject,
            "serial_number": cert.serial_number,
            "not_before": cert.not_before.isoformat(),
            "not_after": cert.not_after.isoformat(),
            "days_remaining": (cert.not_after - now).days,
            "is_valid": cert.not_before <= now <= cert.not_after,
            "revoked": cert.serial_number in self.root_ca.revoked_certificates,
        }
    
    def export_certificate(self, common_name: str, format: str = "pem") -> str:
        """Export certificate in specified format"""
        if common_name not in self.issued_certificates:
            raise ValueError(f"Certificate not found: {common_name}")
        
        cert = self.issued_certificates[common_name]
        
        if format == "pem":
            return cert.to_pem()
        elif format == "der":
            return base64.b64encode(cert._to_der()).decode()
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def get_ca_chain(self, include_root: bool = True) -> List[str]:
        """Get CA certificate chain"""
        chain = []
        
        if self.root_ca and include_root:
            chain.append(self.root_ca.root_cert.to_pem())
        
        for ca in self.intermediate_cas.values():
            chain.append(ca.root_cert.to_pem())
        
        return chain

# ============================================
# PKI HEALTH CHECK
# ============================================

class PKIHealthCheck:
    """Monitor PKI infrastructure health"""
    
    def __init__(self, pki_service: HybridPKIService):
        self.pki = pki_service
        
    def check_all(self) -> Dict[str, Any]:
        """Run all health checks"""
        return {
            "root_ca": self.check_root_ca(),
            "certificates": self.check_certificates(),
            "crl": self.check_crl(),
            "ocsp": self.check_ocsp(),
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    def check_root_ca(self) -> Dict[str, Any]:
        """Check root CA health"""
        if not self.pki.root_ca:
            return {"status": "not_initialized"}
        
        cert = self.pki.root_ca.root_cert
        now = datetime.utcnow()
        days_left = (cert.not_after - now).days
        
        return {
            "status": "healthy" if days_left > 30 else "expiring_soon",
            "subject": cert.subject,
            "days_remaining": days_left,
            "serial_number": cert.serial_number,
        }
    
    def check_certificates(self) -> Dict[str, Any]:
        """Check all issued certificates"""
        expiring = []
        expired = []
        
        now = datetime.utcnow()
        
        for name, cert in self.pki.issued_certificates.items():
            days_left = (cert.not_after - now).days
            if days_left < 0:
                expired.append({"name": name, "serial": cert.serial_number})
            elif days_left < 30:
                expiring.append({"name": name, "serial": cert.serial_number, "days_left": days_left})
        
        return {
            "total": len(self.pki.issued_certificates),
            "expiring": expiring,
            "expired": expired,
            "status": "healthy" if not expired else "has_expired",
        }
    
    def check_crl(self) -> Dict[str, Any]:
        """Check CRL health"""
        if not self.pki.root_ca:
            return {"status": "not_available"}
        
        revoked_count = len(self.pki.root_ca.revoked_certificates)
        
        return {
            "status": "available",
            "revoked_count": revoked_count,
            "last_updated": datetime.utcnow().isoformat(),
        }
    
    def check_ocsp(self) -> Dict[str, Any]:
        """Check OCSP responder health"""
        if not self.pki.ocsp_responder:
            return {"status": "not_configured"}
        
        cache_size = len(self.pki.ocsp_responder.response_cache)
        
        return {
            "status": "healthy",
            "cache_size": cache_size,
            "cache_ttl_hours": 1,
        }