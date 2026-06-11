#!/usr/bin/env python3
"""
Module: Complete Test Suite
File: test_suite.py
Purpose: Comprehensive testing of all Cloud-HNDL modules
Tests: Unit tests, integration tests, security tests, compliance tests
"""

import os
import sys
import json
import unittest
import tempfile
import secrets
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cloud_hndl.crypto_engine import (
    HybridKeyPair, HybridKEM, DualSignature, SignatureKeypairData,
    FileEncryptionEngine, SecureMemory, KeySerializer
)
from cloud_hndl.key_manager import KeyManagementSystem, KeyPurpose
from cloud_hndl.crypto_agility import (
    AlgorithmRegistry, CryptoAgilityManager, AlgorithmCategory, MigrationPolicy
)
from cloud_hndl.tls_hybrid import HybridTLSContext, HybridTLSServer, HybridTLSClient
from cloud_hndl.mtls_pqc import HybridCertificateAuthority, HybridMTLSServer, HybridMTLSClient
from cloud_hndl.hndl_simulation import HNDLSimulator, SimulationConfig
from cloud_hndl.hndl_risk_assessment import (
    HNDLRiskCalculator, DataAsset, DataSensitivity, ThreatModel
)
from cloud_hndl.compliance_validation import (
    ComplianceOrchestrator, ComplianceStandard
)
from cloud_hndl.performance_benchmark import BenchmarkOrchestrator
from cloud_hndl.logging_config import setup_logging, get_logger

logger = get_logger(__name__)

# ============================================
# UNIT TESTS - CRYPTO ENGINE
# ============================================

class TestCryptoEngine(unittest.TestCase):
    """Test core cryptographic engine"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_data = b"Test data for cryptographic operations" * 10
        self.keypair = HybridKeyPair.generate()
        self.sig_keys = DualSignature.generate_keypair()
        
    def test_keypair_generation(self):
        """Test hybrid keypair generation"""
        keypair = HybridKeyPair.generate()
        
        self.assertIsNotNone(keypair)
        self.assertEqual(len(keypair.hybrid_public), 1216)  # 1184 + 32
        self.assertGreater(len(keypair.private_seed), 2000)
        
    def test_kem_encapsulation_decapsulation(self):
        """Test KEM encapsulation/decapsulation"""
        ciphertext, shared_secret_enc = HybridKEM.encapsulate(self.keypair.hybrid_public)
        shared_secret_dec = HybridKEM.decapsulate(self.keypair.private_seed, ciphertext)
        
        self.assertEqual(shared_secret_enc, shared_secret_dec)
        self.assertEqual(len(shared_secret_enc), 32)
        self.assertEqual(len(ciphertext), 1088 + 32)  # ML-KEM-768 + X25519
        
    def test_dual_signature(self):
        """Test dual signature signing and verification"""
        signatures = DualSignature.sign(self.test_data, self.sig_keys)
        
        self.assertIn("classic", signatures)
        self.assertIn("pqc", signatures)
        
        verify_keys = SignatureKeypairData(
            classic_public=self.sig_keys.classic_public,
            classic_private=b"",
            pqc_public=self.sig_keys.pqc_public,
            pqc_private=b"",
        )
        
        valid = DualSignature.verify(self.test_data, signatures, verify_keys)
        self.assertTrue(valid)
        
    def test_signature_tampering(self):
        """Test signature verification fails on tampered data"""
        signatures = DualSignature.sign(self.test_data, self.sig_keys)
        tampered_data = self.test_data + b"tampered"
        
        verify_keys = SignatureKeypairData(
            classic_public=self.sig_keys.classic_public,
            classic_private=b"",
            pqc_public=self.sig_keys.pqc_public,
            pqc_private=b"",
        )
        
        valid = DualSignature.verify(tampered_data, signatures, verify_keys)
        self.assertFalse(valid)
        
    def test_key_serialization(self):
        """Test key serialization to PEM/DER/JWK"""
        # PEM
        pem = KeySerializer.to_pem(self.keypair.hybrid_public)
        self.assertTrue(pem.startswith("-----BEGIN HYBRID PUBLIC KEY-----"))
        
        parsed = KeySerializer.from_pem(pem)
        self.assertEqual(parsed, self.keypair.hybrid_public)
        
        # JWK
        jwk = KeySerializer.to_jwk(self.keypair.hybrid_public)
        self.assertEqual(jwk["kty"], "EC")
        self.assertEqual(jwk["crv"], "X25519")
        self.assertEqual(jwk["pqc_alg"], "ML-KEM-768")
        
        parsed_jwk = KeySerializer.from_jwk(jwk)
        self.assertEqual(parsed_jwk, self.keypair.hybrid_public)
        
    def test_file_encryption_streaming(self):
        """Test streaming file encryption"""
        engine = FileEncryptionEngine(enable_compression=True)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(self.test_data * 100)  # ~4KB
            test_file = f.name
        
        try:
            envelope = engine.encrypt_file_streaming(
                file_path=test_file,
                recipient_hybrid_public=self.keypair.hybrid_public,
                recipient_signature_private=self.sig_keys,
            )
            
            self.assertIn("format_version", envelope)
            self.assertIn("wrapped_key", envelope)
            self.assertIn("chunks", envelope)
            self.assertIn("metadata", envelope)
            self.assertIn("signatures", envelope)
            
            # Decrypt
            output_file = tempfile.NamedTemporaryFile(delete=False, suffix=".bin").name
            sig_public = SignatureKeypairData(
                classic_public=self.sig_keys.classic_public,
                classic_private=b"",
                pqc_public=self.sig_keys.pqc_public,
                pqc_private=b"",
            )
            
            success = engine.decrypt_file_streaming(
                envelope=envelope,
                private_seed=self.keypair.private_seed,
                signature_public_keys=sig_public,
                output_path=output_file,
            )
            
            self.assertTrue(success)
            
            with open(output_file, 'rb') as f:
                decrypted = f.read()
            self.assertEqual(decrypted, self.test_data * 100)
            
        finally:
            os.unlink(test_file)
            if os.path.exists(output_file):
                os.unlink(output_file)
    
    def test_secure_memory_wipe(self):
        """Test secure memory wiping"""
        data = bytearray(secrets.token_bytes(100))
        original = bytes(data)
        
        SecureMemory.wipe(data)
        
        # Check all bytes are zero
        self.assertTrue(all(b == 0 for b in data))
        self.assertNotEqual(bytes(data), original)

# ============================================
# UNIT TESTS - KEY MANAGER
# ============================================

class TestKeyManager(unittest.TestCase):
    """Test key management system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db").name
        self.kms = KeyManagementSystem(db_path=self.temp_db)
        
    def tearDown(self):
        """Clean up test fixtures"""
        if os.path.exists(self.temp_db):
            os.unlink(self.temp_db)
            
    def test_tenant_creation(self):
        """Test tenant creation"""
        tenant = self.kms.create_tenant(
            tenant_id="test_tenant_001",
            name="Test Tenant",
            admin_user_id="admin_001",
        )
        
        self.assertEqual(tenant.tenant_id, "test_tenant_001")
        self.assertEqual(tenant.name, "Test Tenant")
        self.assertEqual(tenant.status, "active")
        self.assertEqual(tenant.encryption_policy, "hybrid")
        
    def test_key_generation(self):
        """Test automatic key generation for tenant"""
        self.kms.create_tenant(
            tenant_id="test_tenant_002",
            name="Test Tenant 2",
            admin_user_id="admin_001",
        )
        
        private_seed, hybrid_public = self.kms.get_active_encryption_key("test_tenant_002")
        
        self.assertIsNotNone(private_seed)
        self.assertEqual(len(hybrid_public), 1216)
        
        sig_private, sig_public = self.kms.get_active_signing_keys("test_tenant_002")
        self.assertIsNotNone(sig_private)
        self.assertIsNotNone(sig_public)
        
    def test_key_rotation(self):
        """Test key rotation"""
        self.kms.create_tenant(
            tenant_id="test_tenant_003",
            name="Test Tenant 3",
            admin_user_id="admin_001",
        )
        
        # Get initial key
        private_seed_v1, public_v1 = self.kms.get_active_encryption_key("test_tenant_003")
        
        # Rotate
        new_key_id = self.kms.rotate_key(
            tenant_id="test_tenant_003",
            key_id="enc_test_tenant_003_v1",
            user_id="admin_001",
            reason="Test rotation",
        )
        
        self.assertEqual(new_key_id, "enc_test_tenant_003_v2")
        
        # Get new key
        private_seed_v2, public_v2 = self.kms.get_active_encryption_key("test_tenant_003")
        
        self.assertNotEqual(private_seed_v1, private_seed_v2)
        self.assertNotEqual(public_v1, public_v2)
        
    def test_access_control(self):
        """Test RBAC access control"""
        self.kms.create_tenant(
            tenant_id="test_tenant_004",
            name="Test Tenant 4",
            admin_user_id="admin_001",
        )
        
        self.kms.grant_access(
            user_id="user_001",
            tenant_id="test_tenant_004",
            role="user",
            permissions=["read", "encrypt"],
        )
        
        self.assertTrue(self.kms.check_access("user_001", "test_tenant_004", "read"))
        self.assertTrue(self.kms.check_access("user_001", "test_tenant_004", "encrypt"))
        self.assertFalse(self.kms.check_access("user_001", "test_tenant_004", "admin"))
        
    def test_audit_logging(self):
        """Test audit logging"""
        self.kms.create_tenant(
            tenant_id="test_tenant_005",
            name="Test Tenant 5",
            admin_user_id="admin_001",
        )
        
        import time
        time.sleep(1)  # Wait for async logging
        
        logs = self.kms.get_audit_logs("test_tenant_005")
        self.assertGreater(len(logs), 0)
        
        # Check log content
        tenant_created_log = next(
            (log for log in logs if log.action == "tenant_created"),
            None
        )
        self.assertIsNotNone(tenant_created_log)
        self.assertEqual(tenant_created_log.tenant_id, "test_tenant_005")
        
    def test_key_backup_restore(self):
        """Test key backup and restore"""
        self.kms.create_tenant(
            tenant_id="test_tenant_006",
            name="Test Tenant 6",
            admin_user_id="admin_001",
        )
        
        # Backup
        backup_result = self.kms.backup_keys("test_tenant_006", "admin_001")
        self.assertIn("backup_file", backup_result)
        self.assertEqual(backup_result["key_count"], 2)
        
        # Restore
        restored = self.kms.restore_keys(
            tenant_id="test_tenant_006",
            backup_file=backup_result["backup_file"],
            user_id="admin_001",
        )
        self.assertEqual(restored, 2)
        
        # Cleanup
        os.unlink(backup_result["backup_file"])

# ============================================
# UNIT TESTS - CRYPTO AGILITY
# ============================================

class TestCryptoAgility(unittest.TestCase):
    """Test cryptographic agility"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.manager = CryptoAgilityManager()
        
    def test_algorithm_selection(self):
        """Test algorithm selection based on policy"""
        algorithm = self.manager.select_algorithm(
            category=AlgorithmCategory.KEY_ENCAPSULATION,
            required_security_level=128,
            prefer_hybrid=True,
        )
        
        self.assertIsNotNone(algorithm)
        self.assertIn(algorithm, AlgorithmRegistry.get_active_kem_algorithms())
        
    def test_keypair_generation(self):
        """Test keypair generation for multiple algorithms"""
        algorithms = ["ML-KEM-768", "X25519", "ML-DSA-65", "Ed25519"]
        
        for algo in algorithms:
            public, private = self.manager.generate_keypair(algo)
            self.assertIsNotNone(public)
            self.assertIsNotNone(private)
            
    def test_key_migration(self):
        """Test key migration between algorithms"""
        # Generate RSA key
        old_public, old_private = self.manager.generate_keypair("RSA-2048")
        
        # Migrate to hybrid
        new_algo, new_public, new_private = self.manager.migrate_key(
            old_algorithm="RSA-2048",
            old_public_key=old_public,
            old_private_key=old_private,
        )
        
        self.assertEqual(new_algo, "ML-KEM-768+X25519")
        self.assertNotEqual(old_public, new_public)
        self.assertNotEqual(old_private, new_private)
        
    def test_health_check(self):
        """Test cryptographic health check"""
        self.manager.active_algorithms = {
            "encryption": "RSA-2048",  # Deprecated
            "signature": "ML-DSA-65",  # Active
        }
        
        health = self.manager.health_check()
        
        self.assertFalse(health["healthy"])
        self.assertEqual(len(health["issues"]), 1)
        self.assertEqual(health["issues"][0]["algorithm"], "RSA-2048")
        
    def test_versioned_crypto(self):
        """Test versioned cryptographic operations"""
        from cloud_hndl.crypto_agility import VersionedCrypto
        
        vc = VersionedCrypto()
        keypair = HybridKeyPair.generate()
        test_data = b"Versioned crypto test data"
        
        encrypted = vc.encrypt_with_version(
            test_data,
            keypair.hybrid_public,
            "ML-KEM-768",
        )
        
        self.assertEqual(encrypted[0:1], b"\x05")  # Version 5 marker
        
        decrypted = vc.decrypt_with_version(
            encrypted,
            keypair.private_seed,
            "ML-KEM-768",
        )
        
        self.assertEqual(decrypted, test_data)

# ============================================
# INTEGRATION TESTS - TLS
# ============================================

class TestTLSIntegration(unittest.TestCase):
    """Test TLS integration"""
    
    def test_hybrid_tls_handshake(self):
        """Test hybrid TLS handshake"""
        server_ctx = HybridTLSContext(is_server=True)
        client_ctx = HybridTLSContext(is_server=False)
        
        server_public = server_ctx.generate_keypair()
        client_public = client_ctx.generate_keypair()
        
        # Server encapsulates
        ciphertext, server_secret = server_ctx.encapsulate_hybrid(client_public)
        
        # Client decapsulates
        client_secret = client_ctx.decapsulate_hybrid(ciphertext)
        
        self.assertEqual(server_secret, client_secret)
        
        # Derive keys
        server_keys = server_ctx.derive_tls_keys()
        client_keys = client_ctx.derive_tls_keys()
        
        self.assertEqual(server_keys["client_handshake_key"], client_keys["client_handshake_key"])
        self.assertEqual(server_keys["server_handshake_key"], client_keys["server_handshake_key"])
        
    def test_mtls_certificate_verification(self):
        """Test mTLS certificate verification"""
        ca = HybridCertificateAuthority("Test CA")
        ca.initialize()
        
        # Issue server certificate
        server_keypair = HybridKeyPair.generate()
        server_cert = ca.issue_certificate(
            subject="server.test.local",
            public_key=server_keypair.hybrid_public,
            dns_names=["server.test.local"],
        )
        
        # Verify certificate
        valid = ca.verify_certificate(server_cert)
        self.assertTrue(valid)
        
        # Test revocation
        ca.revoke_certificate(server_cert.serial_number, "Test revocation")
        valid = ca.verify_certificate(server_cert)
        self.assertFalse(valid)

# ============================================
# INTEGRATION TESTS - HNDL SIMULATION
# ============================================

class TestHNDLSimulation(unittest.TestCase):
    """Test HNDL attack simulation"""
    
    def test_classical_attack(self):
        """Test classical-only attack simulation"""
        config = SimulationConfig(
            algorithms=["classical"],
            attack_iterations=5,
        )
        simulator = HNDLSimulator(config)
        results = simulator.run_simulation()
        
        self.assertGreater(len(results), 0)
        
        # Classical-only should be vulnerable when keys compromised
        for result in results:
            if result.algorithm == "classical" and result.keys_obtained > 0:
                self.assertTrue(result.success)
                
    def test_hybrid_protection(self):
        """Test hybrid protection against HNDL"""
        config = SimulationConfig(
            algorithms=["hybrid"],
            attack_iterations=5,
            key_compromise_scenarios=["classical_only", "pqc_only"],
        )
        simulator = HNDLSimulator(config)
        results = simulator.run_simulation()
        
        # Hybrid should protect when only one key compromised
        for result in results:
            if result.keys_obtained == 1:
                self.assertFalse(result.success)
            elif result.keys_obtained == 2:
                self.assertTrue(result.success)

# ============================================
# INTEGRATION TESTS - RISK ASSESSMENT
# ============================================

class TestRiskAssessment(unittest.TestCase):
    """Test HNDL risk assessment"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.calculator = HNDLRiskCalculator()
        
    def test_asset_risk_calculation(self):
        """Test asset risk calculation"""
        asset = DataAsset(
            asset_id="test_asset_001",
            name="Test Asset",
            sensitivity=DataSensitivity.CONFIDENTIAL,
            retention_period_days=365 * 5,  # 5 years
            encryption_algorithm="RSA-2048",
            signature_algorithm="RSA-PSS-2048",
            created_at=datetime.utcnow(),
            estimated_value_usd=1000000.0,
            regulatory_requirements=["GDPR", "HIPAA"],
        )
        
        risk = self.calculator.calculate_asset_risk(asset)
        
        self.assertIn("risk_score", risk)
        self.assertIn("risk_level", risk)
        self.assertIn("quantum_vulnerability", risk)
        
        # RSA-2048 with 5-year retention should be high risk
        self.assertGreater(risk["risk_score"], 60)
        self.assertEqual(risk["quantum_vulnerability"]["readiness"], "VULNERABLE")
        
    def test_portfolio_risk(self):
        """Test portfolio risk calculation"""
        assets = [
            DataAsset(
                asset_id=f"asset_{i:03d}",
                name=f"Asset {i}",
                sensitivity=DataSensitivity.CONFIDENTIAL,
                retention_period_days=365,
                encryption_algorithm="ML-KEM-768",
                signature_algorithm="ML-DSA-65",
                created_at=datetime.utcnow(),
                estimated_value_usd=100000.0,
            )
            for i in range(10)
        ]
        
        portfolio = self.calculator.calculate_portfolio_risk(assets)
        
        self.assertEqual(portfolio["total_assets"], 10)
        self.assertIn("weighted_risk_score", portfolio)
        self.assertIn("recommendations", portfolio)

# ============================================
# INTEGRATION TESTS - COMPLIANCE
# ============================================

class TestCompliance(unittest.TestCase):
    """Test compliance validation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db").name
        self.kms = KeyManagementSystem(db_path=self.temp_db)
        self.kms.create_tenant("test_tenant", "Test Tenant", "admin")
        self.orchestrator = ComplianceOrchestrator(self.kms)
        
    def tearDown(self):
        """Clean up"""
        if os.path.exists(self.temp_db):
            os.unlink(self.temp_db)
            
    def test_fips_validation(self):
        """Test FIPS 140-3 validation"""
        results = self.orchestrator.validate_all()
        
        self.assertIn(ComplianceStandard.FIPS_140_3.value, results)
        fips_result = results[ComplianceStandard.FIPS_140_3.value]
        
        self.assertIsNotNone(fips_result.status)
        self.assertGreater(fips_result.requirements_total, 0)
        
    def test_nist_175b_validation(self):
        """Test NIST SP 800-175B validation"""
        results = self.orchestrator.validate_all()
        
        self.assertIn(ComplianceStandard.NIST_SP_800_175B.value, results)
        nist_result = results[ComplianceStandard.NIST_SP_800_175B.value]
        
        # Hybrid mode should be compliant
        self.assertIn(nist_result.status.value, ["compliant", "partially_compliant"])
        
    def test_compliance_report(self):
        """Test compliance report generation"""
        report = self.orchestrator.generate_compliance_report()
        
        self.assertIn("report_id", report)
        self.assertIn("summary", report)
        self.assertIn("detailed_results", report)
        self.assertIn("next_validation", report)

# ============================================
# PERFORMANCE TESTS
# ============================================

class TestPerformance(unittest.TestCase):
    """Test performance benchmarks"""
    
    def test_benchmark_suite(self):
        """Test benchmark suite runs"""
        orchestrator = BenchmarkOrchestrator(iterations=10)
        suite = orchestrator.run_full_suite()
        
        self.assertIsNotNone(suite.suite_id)
        self.assertGreater(len(suite.results), 0)
        self.assertIn("total_tests", suite.summary)
        
    def test_algorithm_comparison(self):
        """Test algorithm comparison"""
        orchestrator = BenchmarkOrchestrator(iterations=10)
        comparison = orchestrator.compare_algorithms("key_generation")
        
        if "error" not in comparison:
            self.assertIn("fastest", comparison)
            self.assertIn("slowest", comparison)
            self.assertIn("algorithms", comparison)

# ============================================
# TEST RUNNER
# ============================================

def run_all_tests():
    """Run all test suites"""
    setup_logging("INFO")
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestKeyManager))
    suite.addTests(loader.loadTestsFromTestCase(TestCryptoAgility))
    suite.addTests(loader.loadTestsFromTestCase(TestTLSIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestHNDLSimulation))
    suite.addTests(loader.loadTestsFromTestCase(TestRiskAssessment))
    suite.addTests(loader.loadTestsFromTestCase(TestCompliance))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformance))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Generate report
    report = {
        "timestamp": datetime.utcnow().isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
    }
    
    # Save report
    with open("test_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    
    logger.info(f"Tests completed: {report['tests_run']} run, {report['failures']} failures, {report['errors']} errors")
    
    return result

def run_specific_test(test_class: str):
    """Run specific test class"""
    setup_logging("INFO")
    
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(f"__main__.{test_class}")
    
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Cloud-HNDL Test Suite")
    parser.add_argument("--test", help="Run specific test class")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        setup_logging("DEBUG")
    else:
        setup_logging("INFO")
    
    if args.test:
        result = run_specific_test(args.test)
    else:
        result = run_all_tests()
    
    sys.exit(0 if result.wasSuccessful() else 1)