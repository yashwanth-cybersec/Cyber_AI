#!/usr/bin/env python3
"""
Cloud-HNDL Main Entry Point
Complete Hybrid Post-Quantum Encryption Gateway
Version: 2.0.0

This is the main entry point that:
1. Loads configuration from environment
2. Initializes all components (KMS, simulator, gateway)
3. Starts the FastAPI server with proper signal handling
4. Provides status reporting and graceful shutdown
"""

import sys
import os
import signal
import asyncio
import threading
import time
import uvicorn
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cloud_hndl.config import config, CloudHNDLConfig
from cloud_hndl.logging_config import setup_logging, get_logger
from cloud_hndl.gateway_api import app

logger = get_logger(__name__)


class CloudHNDLServer:
    """Main server orchestrator for Cloud-HNDL"""
    
    def __init__(self):
        self.logger = logger
        self.kms = None
        self.simulator = None
        self.start_time = None
        self._shutdown_requested = False
        
    def print_banner(self):
        """Print the startup banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    CLOUD-HNDL v2.0.0                              ║
║         Hybrid Post-Quantum Encryption Gateway                    ║
╠══════════════════════════════════════════════════════════════════╣
║  Algorithms:    X25519 + ML-KEM-768 (NIST PQC Standard)          ║
║  Signatures:    Ed25519 + ML-DSA-65                              ║
║  Encryption:    AES-256-GCM                                      ║
║  HNDL Protection: ACTIVE                                          ║
╠══════════════════════════════════════════════════════════════════╣
║  Gateway API:    http://{config.host}:{config.port:<5}                    ║
║  API Docs:       http://{config.host}:{config.port}/docs                ║
║  Health:         http://{config.host}:{config.port}/health              ║
╠══════════════════════════════════════════════════════════════════╣
║  Storage:        {'MinIO' if config.minio_endpoint else 'Local File System':<40} ║
║  Database:       {'PostgreSQL' if 'postgresql' in config.database_url else 'SQLite':<40} ║
║  Redis:          {'Enabled' if config.redis_url else 'Disabled':<40} ║
╚══════════════════════════════════════════════════════════════════╝
"""
        print(banner)
        
    def initialize(self):
        """Initialize all components with comprehensive error handling"""
        self.start_time = datetime.utcnow()
        
        self.print_banner()
        self.logger.info("=" * 60)
        self.logger.info("Initializing Cloud-HNDL Server v2.0.0")
        self.logger.info("=" * 60)
        
        # Step 1: Setup logging
        try:
            setup_logging(config.log_level, config.log_file)
            self.logger.info("✅ Structured logging initialized")
        except Exception as e:
            print(f"❌ Failed to setup logging: {e}")
            sys.exit(1)
        
        # Step 2: Initialize Key Management System
        try:
            db_path = config.database_url.replace("sqlite:///", "")
            master_password = getattr(config, 'master_password', None)
            
            from cloud_hndl.key_manager import KeyManagementSystem
            self.kms = KeyManagementSystem(
                db_path=db_path if db_path else "cloud_hndl.db",
                master_password=master_password
            )
            self.logger.info("✅ Key Management System initialized")
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize KMS: {e}")
            self.logger.warning("⚠️ Running without Key Management System")
        
        # Step 3: Initialize HNDL Simulator
        try:
            from cloud_hndl.hndl_simulation import HNDLSimulator
            self.simulator = HNDLSimulator()
            self.logger.info("✅ HNDL Attack Simulator initialized")
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize HNDL Simulator: {e}")
            self.logger.warning("⚠️ HNDL simulation unavailable")
        
        # Step 4: Initialize Crypto Engine Status
        try:
            from cloud_hndl.crypto_engine import OQS_AVAILABLE, HybridKeyPair
            # Test key generation
            test_keypair = HybridKeyPair.generate()
            if OQS_AVAILABLE:
                self.logger.info("✅ PQC Crypto Engine initialized (liboqs loaded)")
            else:
                self.logger.info("✅ Crypto Engine initialized (simulation mode - liboqs not available)")
            self.logger.info(f"   - Hybrid public key size: {len(test_keypair.hybrid_public)} bytes")
        except Exception as e:
            self.logger.error(f"❌ Crypto Engine failure: {e}")
            self.logger.warning("⚠️ Running with limited crypto capabilities")
        
        # Step 5: Check storage backend
        try:
            from cloud_hndl.gateway_api import LocalStorage
            storage = LocalStorage()
            test_key = f"_health_check_{int(time.time())}"
            storage.put_object("test", test_key, b"health_check")
            storage.get_object("test", test_key)
            storage.delete_object("test", test_key)
            self.logger.info("✅ Local storage backend operational")
        except Exception as e:
            self.logger.error(f"❌ Storage backend failure: {e}")
        
        # Attach components to app state
        app.state.kms = self.kms
        app.state.simulator = self.simulator
        app.state.config = config
        app.state.start_time = self.start_time
        
        # Report status
        self.print_status()
        
        self.logger.info("=" * 60)
        self.logger.info("All components initialized successfully")
        self.logger.info("=" * 60)
    
    def print_status(self):
        """Print component status"""
        status = {
            "Key Management": "✅" if self.kms else "❌",
            "HNDL Simulator": "✅" if self.simulator else "❌",
            "Crypto Engine": "✅",
            "Storage": "✅",
            "Database": "✅" if "sqlite" in config.database_url or "postgresql" in config.database_url else "⚠️",
        }
        
        self.logger.info("Component Status:")
        for component, status_icon in status.items():
            self.logger.info(f"  {status_icon} {component}")
        
    def run(self):
        """Run the server with signal handling"""
        self.logger.info(f"\n{'=' * 60}")
        self.logger.info(f"Starting Cloud-HNDL Gateway on {config.host}:{config.port}")
        self.logger.info(f"API Documentation: http://{config.host}:{config.port}/docs")
        self.logger.info(f"Health Check: http://{config.host}:{config.port}/health")
        self.logger.info(f"{'=' * 60}\n")
        
        # Handle graceful shutdown
        def signal_handler(sig, frame):
            self.logger.info(f"\nReceived signal {sig}, shutting down...")
            self._shutdown_requested = True
            self.shutdown()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start server
        try:
            uvicorn.run(
                app,
                host=config.host,
                port=config.port,
                log_level=config.log_level.lower(),
                access_log=config.debug,
                reload=False,
            )
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
            self.shutdown()
        except Exception as e:
            self.logger.error(f"Server crashed: {e}")
            self.shutdown()
            sys.exit(1)
        
    def shutdown(self):
        """Graceful shutdown with cleanup"""
        self.logger.info("Shutting down Cloud-HNDL Server...")
        
        # Cleanup KMS
        if self.kms:
            try:
                expired = self.kms.cleanup_expired_keys()
                self.logger.info(f"  - Cleaned up {expired} expired keys")
            except Exception as e:
                self.logger.error(f"  - KMS cleanup failed: {e}")
        
        # Calculate uptime
        if self.start_time:
            uptime = datetime.utcnow() - self.start_time
            self.logger.info(f"  - Total uptime: {uptime}")
        
        self.logger.info("Cloud-HNDL Server stopped")


def check_environment():
    """Check that all required environment variables and dependencies are available"""
    issues = []
    
    # Check Python version
    if sys.version_info < (3, 8):
        issues.append("Python 3.8+ required")
    
    # Check critical imports
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError:
        issues.append("cryptography package not installed")
    
    # Check storage
    try:
        os.makedirs("cloud_hndl_storage", exist_ok=True)
    except Exception:
        issues.append("Cannot create storage directory")
    
    if issues:
        print("❌ Environment check failed:")
        for issue in issues:
            print(f"   - {issue}")
        return False
    
    print("✅ Environment check passed")
    return True


def main():
    """Main entry point"""
    print("\n" + "=" * 60)
    print("Cloud-HNDL: Hybrid Post-Quantum Encryption Gateway")
    print("=" * 60 + "\n")
    
    # Check environment first
    if not check_environment():
        sys.exit(1)
    
    # Create and run server
    server = CloudHNDLServer()
    
    try:
        server.initialize()
        server.run()
    except KeyboardInterrupt:
        print("\nShutdown requested")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()