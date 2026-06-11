"""Configuration management for Cloud-HNDL"""
import os
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class CloudHNDLConfig:
    """Central configuration for Cloud-HNDL"""
    
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    
    # Database settings
    database_url: str = "sqlite:///cloud_hndl.db"
    redis_url: str = "redis://localhost:6379"
    
    # MinIO settings
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "cloud-hndl-bucket"
    minio_secure: bool = False
    
    # Crypto settings
    default_algorithm: str = "hybrid"
    key_rotation_days: int = 90
    pbkdf2_iterations: int = 100000
    
    # Rate limiting
    rate_limit_requests: int = 1000
    rate_limit_window: int = 60
    
    # Circuit breaker
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 60
    
    # HSM settings (optional)
    hsm_enabled: bool = False
    hsm_config: Optional[dict] = None
    
    # PKI settings
    pki_enabled: bool = False
    pki_ca_url: Optional[str] = None
    
    # TLS settings
    tls_enabled: bool = False
    tls_cert_file: Optional[str] = None
    tls_key_file: Optional[str] = None
    
    # Metrics
    metrics_enabled: bool = True
    metrics_port: int = 9090
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    log_file: Optional[str] = "cloud_hndl.log"
    
    @classmethod
    def from_env(cls) -> "CloudHNDLConfig":
        """Load configuration from environment variables"""
        config = cls()
        
        # Server
        config.host = os.getenv("CLOUD_HNDL_HOST", config.host)
        config.port = int(os.getenv("CLOUD_HNDL_PORT", config.port))
        config.debug = os.getenv("CLOUD_HNDL_DEBUG", "").lower() == "true"
        
        # Database
        config.database_url = os.getenv("DATABASE_URL", config.database_url)
        config.redis_url = os.getenv("REDIS_URL", config.redis_url)
        
        # MinIO
        config.minio_endpoint = os.getenv("MINIO_ENDPOINT", config.minio_endpoint)
        config.minio_access_key = os.getenv("MINIO_ACCESS_KEY", config.minio_access_key)
        config.minio_secret_key = os.getenv("MINIO_SECRET_KEY", config.minio_secret_key)
        config.minio_bucket = os.getenv("MINIO_BUCKET", config.minio_bucket)
        
        # Crypto
        config.default_algorithm = os.getenv("DEFAULT_ALGORITHM", config.default_algorithm)
        config.key_rotation_days = int(os.getenv("KEY_ROTATION_DAYS", config.key_rotation_days))
        
        # HSM
        config.hsm_enabled = os.getenv("HSM_ENABLED", "").lower() == "true"
        
        # PKI
        config.pki_enabled = os.getenv("PKI_ENABLED", "").lower() == "true"
        config.pki_ca_url = os.getenv("PKI_CA_URL")
        
        # TLS
        config.tls_enabled = os.getenv("TLS_ENABLED", "").lower() == "true"
        config.tls_cert_file = os.getenv("TLS_CERT_FILE")
        config.tls_key_file = os.getenv("TLS_KEY_FILE")
        
        # Logging
        config.log_level = os.getenv("LOG_LEVEL", config.log_level)
        config.log_file = os.getenv("LOG_FILE", config.log_file)
        
        return config

# Global configuration instance
config = CloudHNDLConfig.from_env()