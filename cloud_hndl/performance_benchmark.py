#!/usr/bin/env python3
"""
Module: Performance Benchmarking
File: performance_benchmark.py
Purpose: Comprehensive performance testing of cryptographic operations
Tests: Key generation, encryption, decryption, signing, verification
"""

import time
import json
import statistics
import multiprocessing as mp
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import psutil
import platform

from .crypto_engine import (
    HybridKeyPair, HybridKEM, DualSignature,
    FileEncryptionEngine, MLKEM768_PUBLIC_KEY_SIZE
)
from .crypto_agility import AlgorithmRegistry, AlgorithmCategory
from .tls_hybrid import HybridTLSContext, HybridTLSServer, HybridTLSClient
from .logging_config import get_logger

logger = get_logger(__name__)

# ============================================
# BENCHMARK DATA STRUCTURES
# ============================================

@dataclass
class BenchmarkResult:
    """Result of a single benchmark"""
    operation: str
    algorithm: str
    iterations: int
    total_time_seconds: float
    mean_time_ms: float
    median_time_ms: float
    p95_time_ms: float
    p99_time_ms: float
    min_time_ms: float
    max_time_ms: float
    std_dev_ms: float
    throughput_ops_per_sec: float
    memory_usage_mb: float
    cpu_usage_percent: float

@dataclass
class BenchmarkSuite:
    """Complete benchmark suite results"""
    suite_id: str
    timestamp: datetime
    system_info: Dict[str, Any]
    results: List[BenchmarkResult]
    summary: Dict[str, Any]

# ============================================
# SYSTEM INFORMATION
# ============================================

class SystemInfo:
    """Collect system information for benchmarks"""
    
    @staticmethod
    def collect() -> Dict[str, Any]:
        """Collect comprehensive system information"""
        return {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "cpu_count": mp.cpu_count(),
            "cpu_physical": psutil.cpu_count(logical=False),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "python_version": platform.python_version(),
            "system": platform.system(),
            "machine": platform.machine(),
            "timestamp": datetime.utcnow().isoformat(),
        }

# ============================================
# PERFORMANCE TIMER
# ============================================

class PerformanceTimer:
    """High-precision performance timer"""
    
    def __init__(self):
        self.times: List[float] = []
        self.start_time: Optional[float] = None
        self.memory_start: Optional[int] = None
        
    def __enter__(self):
        self.start_time = time.perf_counter()
        self.memory_start = psutil.Process().memory_info().rss
        return self
        
    def __exit__(self, *args):
        elapsed = time.perf_counter() - self.start_time
        self.times.append(elapsed)
        
    def record(self, func: Callable, *args, **kwargs) -> float:
        """Time a function execution"""
        start = time.perf_counter()
        func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        self.times.append(elapsed)
        return elapsed
    
    def get_memory_delta_mb(self) -> float:
        """Get memory usage delta in MB"""
        current = psutil.Process().memory_info().rss
        if self.memory_start:
            return (current - self.memory_start) / (1024 * 1024)
        return 0.0
    
    def get_statistics(self) -> Dict[str, float]:
        """Calculate statistics from recorded times"""
        if not self.times:
            return {}
        
        sorted_times = sorted(self.times)
        n = len(sorted_times)
        
        return {
            "mean": statistics.mean(self.times) * 1000,
            "median": statistics.median(self.times) * 1000,
            "p95": sorted_times[int(n * 0.95)] * 1000 if n > 1 else self.times[0] * 1000,
            "p99": sorted_times[int(n * 0.99)] * 1000 if n > 1 else self.times[0] * 1000,
            "min": min(self.times) * 1000,
            "max": max(self.times) * 1000,
            "std_dev": statistics.stdev(self.times) * 1000 if n > 1 else 0.0,
        }

# ============================================
# CRYPTO BENCHMARKS
# ============================================

class CryptoBenchmark:
    """Benchmark cryptographic operations"""
    
    def __init__(self, iterations: int = 1000):
        self.iterations = iterations
        
    def benchmark_key_generation(self) -> List[BenchmarkResult]:
        """Benchmark key generation for all algorithms"""
        results = []
        
        # Classical algorithms
        algorithms = ["RSA-2048", "RSA-4096", "X25519", "Ed25519", "ECDSA-P256"]
        
        # PQC algorithms
        algorithms.extend(["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"])
        algorithms.extend(["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
        
        for algo in algorithms:
            logger.info(f"Benchmarking key generation: {algo}")
            timer = PerformanceTimer()
            
            for _ in range(self.iterations):
                if algo.startswith("ML-KEM"):
                    import oqs
                    kem = oqs.KeyEncapsulation(algo)
                    with timer:
                        kem.generate_keypair()
                elif algo == "X25519":
                    from cryptography.hazmat.primitives.asymmetric import x25519
                    with timer:
                        x25519.X25519PrivateKey.generate()
                elif algo == "Ed25519":
                    from cryptography.hazmat.primitives.asymmetric import ed25519
                    with timer:
                        ed25519.Ed25519PrivateKey.generate()
                elif algo.startswith("RSA"):
                    from cryptography.hazmat.primitives.asymmetric import rsa
                    key_size = int(algo.split("-")[1])
                    with timer:
                        rsa.generate_private_key(public_exponent=65537, key_size=key_size)
                elif algo.startswith("ECDSA"):
                    from cryptography.hazmat.primitives.asymmetric import ec
                    with timer:
                        ec.generate_private_key(ec.SECP256R1())
            
            stats = timer.get_statistics()
            results.append(BenchmarkResult(
                operation="key_generation",
                algorithm=algo,
                iterations=self.iterations,
                total_time_seconds=sum(timer.times),
                mean_time_ms=stats.get("mean", 0),
                median_time_ms=stats.get("median", 0),
                p95_time_ms=stats.get("p95", 0),
                p99_time_ms=stats.get("p99", 0),
                min_time_ms=stats.get("min", 0),
                max_time_ms=stats.get("max", 0),
                std_dev_ms=stats.get("std_dev", 0),
                throughput_ops_per_sec=self.iterations / sum(timer.times),
                memory_usage_mb=timer.get_memory_delta_mb(),
                cpu_usage_percent=0.0,
            ))
        
        return results
    
    def benchmark_encapsulation(self) -> List[BenchmarkResult]:
        """Benchmark KEM encapsulation"""
        results = []
        algorithms = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519", "HYBRID"]
        
        for algo in algorithms:
            logger.info(f"Benchmarking encapsulation: {algo}")
            timer = PerformanceTimer()
            
            if algo == "HYBRID":
                keypair = HybridKeyPair.generate()
                for _ in range(self.iterations):
                    with timer:
                        HybridKEM.encapsulate(keypair.hybrid_public)
            elif algo.startswith("ML-KEM"):
                import oqs
                kem = oqs.KeyEncapsulation(algo)
                public = kem.generate_keypair()
                for _ in range(self.iterations):
                    with timer:
                        kem.encapsulate(public)
            elif algo == "X25519":
                from cryptography.hazmat.primitives.asymmetric import x25519
                private = x25519.X25519PrivateKey.generate()
                public = private.public_key()
                for _ in range(self.iterations):
                    ephemeral = x25519.X25519PrivateKey.generate()
                    with timer:
                        ephemeral.exchange(public)
            
            stats = timer.get_statistics()
            results.append(BenchmarkResult(
                operation="encapsulation",
                algorithm=algo,
                iterations=self.iterations,
                total_time_seconds=sum(timer.times),
                mean_time_ms=stats.get("mean", 0),
                median_time_ms=stats.get("median", 0),
                p95_time_ms=stats.get("p95", 0),
                p99_time_ms=stats.get("p99", 0),
                min_time_ms=stats.get("min", 0),
                max_time_ms=stats.get("max", 0),
                std_dev_ms=stats.get("std_dev", 0),
                throughput_ops_per_sec=self.iterations / sum(timer.times),
                memory_usage_mb=timer.get_memory_delta_mb(),
                cpu_usage_percent=0.0,
            ))
        
        return results
    
    def benchmark_signature(self) -> List[BenchmarkResult]:
        """Benchmark signature operations"""
        results = []
        algorithms = ["Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "HYBRID"]
        test_data = b"Benchmark test data for signature" * 10
        
        for algo in algorithms:
            logger.info(f"Benchmarking signature: {algo}")
            
            if algo == "HYBRID":
                sig_keys = DualSignature.generate_keypair()
                sign_timer = PerformanceTimer()
                verify_timer = PerformanceTimer()
                
                for _ in range(self.iterations):
                    with sign_timer:
                        signatures = DualSignature.sign(test_data, sig_keys)
                    with verify_timer:
                        DualSignature.verify(
                            test_data, signatures,
                            SignatureKeypairData(
                                classic_public=sig_keys.classic_public,
                                classic_private=b"",
                                pqc_public=sig_keys.pqc_public,
                                pqc_private=b"",
                            )
                        )
                
                sign_stats = sign_timer.get_statistics()
                verify_stats = verify_timer.get_statistics()
                
                results.append(BenchmarkResult(
                    operation="sign",
                    algorithm=algo,
                    iterations=self.iterations,
                    total_time_seconds=sum(sign_timer.times),
                    mean_time_ms=sign_stats.get("mean", 0),
                    median_time_ms=sign_stats.get("median", 0),
                    p95_time_ms=sign_stats.get("p95", 0),
                    p99_time_ms=sign_stats.get("p99", 0),
                    min_time_ms=sign_stats.get("min", 0),
                    max_time_ms=sign_stats.get("max", 0),
                    std_dev_ms=sign_stats.get("std_dev", 0),
                    throughput_ops_per_sec=self.iterations / sum(sign_timer.times),
                    memory_usage_mb=sign_timer.get_memory_delta_mb(),
                    cpu_usage_percent=0.0,
                ))
                
                results.append(BenchmarkResult(
                    operation="verify",
                    algorithm=algo,
                    iterations=self.iterations,
                    total_time_seconds=sum(verify_timer.times),
                    mean_time_ms=verify_stats.get("mean", 0),
                    median_time_ms=verify_stats.get("median", 0),
                    p95_time_ms=verify_stats.get("p95", 0),
                    p99_time_ms=verify_stats.get("p99", 0),
                    min_time_ms=verify_stats.get("min", 0),
                    max_time_ms=verify_stats.get("max", 0),
                    std_dev_ms=verify_stats.get("std_dev", 0),
                    throughput_ops_per_sec=self.iterations / sum(verify_timer.times),
                    memory_usage_mb=verify_timer.get_memory_delta_mb(),
                    cpu_usage_percent=0.0,
                ))
            else:
                import oqs
                sig = oqs.Signature(algo)
                public = sig.generate_keypair()
                private = sig.export_secret_key()
                
                sign_timer = PerformanceTimer()
                verify_timer = PerformanceTimer()
                
                for _ in range(self.iterations):
                    sig.import_secret_key(private)
                    with sign_timer:
                        signature = sig.sign(test_data)
                    sig.import_public_key(public)
                    with verify_timer:
                        sig.verify(test_data, signature)
                
                sign_stats = sign_timer.get_statistics()
                verify_stats = verify_timer.get_statistics()
                
                results.append(BenchmarkResult(
                    operation="sign",
                    algorithm=algo,
                    iterations=self.iterations,
                    total_time_seconds=sum(sign_timer.times),
                    mean_time_ms=sign_stats.get("mean", 0),
                    median_time_ms=sign_stats.get("median", 0),
                    p95_time_ms=sign_stats.get("p95", 0),
                    p99_time_ms=sign_stats.get("p99", 0),
                    min_time_ms=sign_stats.get("min", 0),
                    max_time_ms=sign_stats.get("max", 0),
                    std_dev_ms=sign_stats.get("std_dev", 0),
                    throughput_ops_per_sec=self.iterations / sum(sign_timer.times),
                    memory_usage_mb=sign_timer.get_memory_delta_mb(),
                    cpu_usage_percent=0.0,
                ))
        
        return results
    
    def benchmark_file_encryption(self, file_sizes_mb: List[int] = None) -> List[BenchmarkResult]:
        """Benchmark file encryption with different sizes"""
        if file_sizes_mb is None:
            file_sizes_mb = [1, 10, 50, 100]
        
        results = []
        engine = FileEncryptionEngine(enable_compression=True)
        
        import tempfile
        import os
        import secrets
        
        for size_mb in file_sizes_mb:
            logger.info(f"Benchmarking file encryption: {size_mb} MB")
            
            # Create test file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
                f.write(secrets.token_bytes(size_mb * 1024 * 1024))
                test_file = f.name
            
            try:
                # Generate keys
                keypair = HybridKeyPair.generate()
                sig_keys = DualSignature.generate_keypair()
                
                timer = PerformanceTimer()
                
                for _ in range(min(5, self.iterations // 10)):
                    with timer:
                        envelope = engine.encrypt_file_streaming(
                            file_path=test_file,
                            recipient_hybrid_public=keypair.hybrid_public,
                            recipient_signature_private=sig_keys,
                        )
                
                stats = timer.get_statistics()
                results.append(BenchmarkResult(
                    operation="file_encryption",
                    algorithm=f"HYBRID_AES256",
                    iterations=len(timer.times),
                    total_time_seconds=sum(timer.times),
                    mean_time_ms=stats.get("mean", 0),
                    median_time_ms=stats.get("median", 0),
                    p95_time_ms=stats.get("p95", 0),
                    p99_time_ms=stats.get("p99", 0),
                    min_time_ms=stats.get("min", 0),
                    max_time_ms=stats.get("max", 0),
                    std_dev_ms=stats.get("std_dev", 0),
                    throughput_ops_per_sec=size_mb / (sum(timer.times) / len(timer.times)),
                    memory_usage_mb=timer.get_memory_delta_mb(),
                    cpu_usage_percent=0.0,
                ))
            finally:
                os.unlink(test_file)
        
        return results

# ============================================
# TLS BENCHMARKS
# ============================================

class TLSBenchmark:
    """Benchmark TLS handshake performance"""
    
    def __init__(self, iterations: int = 100):
        self.iterations = iterations
        
    def benchmark_handshake(self) -> List[BenchmarkResult]:
        """Benchmark hybrid TLS handshake"""
        results = []
        
        logger.info("Benchmarking TLS handshake")
        timer = PerformanceTimer()
        
        for _ in range(self.iterations):
            # Create server and client contexts
            server_ctx = HybridTLSContext(is_server=True)
            server_ctx.generate_keypair()
            server_ctx.generate_certificate()
            
            client_ctx = HybridTLSContext(is_server=False)
            client_ctx.generate_keypair()
            
            with timer:
                # Simulate handshake
                client_public = client_ctx.hybrid_keypair.hybrid_public
                ciphertext, _ = server_ctx.encapsulate_hybrid(client_public)
                client_ctx.decapsulate_hybrid(ciphertext)
                
                server_ctx.derive_tls_keys()
                client_ctx.derive_tls_keys()
        
        stats = timer.get_statistics()
        results.append(BenchmarkResult(
            operation="tls_handshake",
            algorithm="HYBRID",
            iterations=self.iterations,
            total_time_seconds=sum(timer.times),
            mean_time_ms=stats.get("mean", 0),
            median_time_ms=stats.get("median", 0),
            p95_time_ms=stats.get("p95", 0),
            p99_time_ms=stats.get("p99", 0),
            min_time_ms=stats.get("min", 0),
            max_time_ms=stats.get("max", 0),
            std_dev_ms=stats.get("std_dev", 0),
            throughput_ops_per_sec=self.iterations / sum(timer.times),
            memory_usage_mb=timer.get_memory_delta_mb(),
            cpu_usage_percent=0.0,
        ))
        
        return results

# ============================================
# CONCURRENCY BENCHMARKS
# ============================================

class ConcurrencyBenchmark:
    """Benchmark concurrent operations"""
    
    def __init__(self, iterations: int = 1000, max_workers: int = None):
        self.iterations = iterations
        self.max_workers = max_workers or mp.cpu_count()
        
    def benchmark_concurrent_encryption(self) -> List[BenchmarkResult]:
        """Benchmark concurrent encryption operations"""
        results = []
        
        keypair = HybridKeyPair.generate()
        test_data = b"Concurrent benchmark test data" * 100
        
        def encrypt_task():
            return HybridKEM.encapsulate(keypair.hybrid_public)
        
        for workers in [1, 2, 4, 8, 16]:
            logger.info(f"Benchmarking concurrent encryption: {workers} workers")
            timer = PerformanceTimer()
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(encrypt_task) for _ in range(self.iterations)]
                for future in futures:
                    with timer:
                        future.result()
            
            stats = timer.get_statistics()
            results.append(BenchmarkResult(
                operation="concurrent_encryption",
                algorithm=f"HYBRID_{workers}workers",
                iterations=self.iterations,
                total_time_seconds=sum(timer.times),
                mean_time_ms=stats.get("mean", 0),
                median_time_ms=stats.get("median", 0),
                p95_time_ms=stats.get("p95", 0),
                p99_time_ms=stats.get("p99", 0),
                min_time_ms=stats.get("min", 0),
                max_time_ms=stats.get("max", 0),
                std_dev_ms=stats.get("std_dev", 0),
                throughput_ops_per_sec=self.iterations / sum(timer.times),
                memory_usage_mb=timer.get_memory_delta_mb(),
                cpu_usage_percent=0.0,
            ))
        
        return results

# ============================================
# BENCHMARK ORCHESTRATOR
# ============================================

class BenchmarkOrchestrator:
    """Orchestrate complete benchmark suite"""
    
    def __init__(self, iterations: int = 1000):
        self.iterations = iterations
        self.crypto_bench = CryptoBenchmark(iterations)
        self.tls_bench = TLSBenchmark(min(iterations, 100))
        self.concurrent_bench = ConcurrencyBenchmark(iterations)
        
    def run_full_suite(self) -> BenchmarkSuite:
        """Run complete benchmark suite"""
        logger.info("Starting full benchmark suite")
        
        all_results = []
        
        # Crypto benchmarks
        all_results.extend(self.crypto_bench.benchmark_key_generation())
        all_results.extend(self.crypto_bench.benchmark_encapsulation())
        all_results.extend(self.crypto_bench.benchmark_signature())
        all_results.extend(self.crypto_bench.benchmark_file_encryption())
        
        # TLS benchmarks
        all_results.extend(self.tls_bench.benchmark_handshake())
        
        # Concurrency benchmarks
        all_results.extend(self.concurrent_bench.benchmark_concurrent_encryption())
        
        # Generate summary
        summary = self._generate_summary(all_results)
        
        logger.info("Benchmark suite completed")
        
        return BenchmarkSuite(
            suite_id=f"BENCH-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            timestamp=datetime.utcnow(),
            system_info=SystemInfo.collect(),
            results=all_results,
            summary=summary,
        )
    
    def _generate_summary(self, results: List[BenchmarkResult]) -> Dict[str, Any]:
        """Generate benchmark summary"""
        summary = {
            "total_tests": len(results),
            "fastest_operation": None,
            "slowest_operation": None,
            "algorithms_compared": set(),
            "operations_compared": set(),
        }
        
        if results:
            # Find fastest and slowest
            fastest = min(results, key=lambda r: r.mean_time_ms)
            slowest = max(results, key=lambda r: r.mean_time_ms)
            
            summary["fastest_operation"] = {
                "operation": fastest.operation,
                "algorithm": fastest.algorithm,
                "mean_time_ms": fastest.mean_time_ms,
            }
            summary["slowest_operation"] = {
                "operation": slowest.operation,
                "algorithm": slowest.algorithm,
                "mean_time_ms": slowest.mean_time_ms,
            }
            
            # Collect algorithms and operations
            for r in results:
                summary["algorithms_compared"].add(r.algorithm)
                summary["operations_compared"].add(r.operation)
            
            summary["algorithms_compared"] = list(summary["algorithms_compared"])
            summary["operations_compared"] = list(summary["operations_compared"])
        
        return summary
    
    def export_results(self, suite: BenchmarkSuite, format: str = "json") -> str:
        """Export benchmark results"""
        data = {
            "suite_id": suite.suite_id,
            "timestamp": suite.timestamp.isoformat(),
            "system_info": suite.system_info,
            "summary": suite.summary,
            "results": [
                {
                    "operation": r.operation,
                    "algorithm": r.algorithm,
                    "iterations": r.iterations,
                    "mean_time_ms": r.mean_time_ms,
                    "p95_time_ms": r.p95_time_ms,
                    "p99_time_ms": r.p99_time_ms,
                    "throughput_ops_per_sec": r.throughput_ops_per_sec,
                    "memory_usage_mb": r.memory_usage_mb,
                }
                for r in suite.results
            ]
        }
        
        if format == "json":
            return json.dumps(data, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def compare_algorithms(self, operation: str) -> Dict[str, Any]:
        """Compare algorithms for a specific operation"""
        suite = self.run_full_suite()
        
        operation_results = [r for r in suite.results if r.operation == operation]
        
        if not operation_results:
            return {"error": f"No results for operation: {operation}"}
        
        # Sort by performance
        sorted_results = sorted(operation_results, key=lambda r: r.mean_time_ms)
        
        comparison = {
            "operation": operation,
            "algorithms": [],
            "fastest": {
                "algorithm": sorted_results[0].algorithm,
                "mean_time_ms": sorted_results[0].mean_time_ms,
                "throughput": sorted_results[0].throughput_ops_per_sec,
            },
            "slowest": {
                "algorithm": sorted_results[-1].algorithm,
                "mean_time_ms": sorted_results[-1].mean_time_ms,
                "throughput": sorted_results[-1].throughput_ops_per_sec,
            },
        }
        
        for r in sorted_results:
            comparison["algorithms"].append({
                "algorithm": r.algorithm,
                "mean_time_ms": r.mean_time_ms,
                "p95_time_ms": r.p95_time_ms,
                "throughput": r.throughput_ops_per_sec,
                "relative_speed": sorted_results[0].mean_time_ms / r.mean_time_ms,
            })
        
        return comparison

# ============================================
# PERFORMANCE MONITOR
# ============================================

class PerformanceMonitor:
    """Continuous performance monitoring"""
    
    def __init__(self, orchestrator: BenchmarkOrchestrator):
        self.orchestrator = orchestrator
        self.history: List[Dict] = []
        self.baseline: Optional[Dict] = None
        
    def establish_baseline(self):
        """Establish performance baseline"""
        suite = self.orchestrator.run_full_suite()
        self.baseline = {
            "suite_id": suite.suite_id,
            "timestamp": suite.timestamp,
            "results": {
                r.operation + "_" + r.algorithm: r.mean_time_ms
                for r in suite.results
            }
        }
        logger.info("Performance baseline established")
        
    def check_regression(self, threshold_percent: float = 10.0) -> List[Dict]:
        """Check for performance regression"""
        if not self.baseline:
            self.establish_baseline()
            return []
        
        current = self.orchestrator.run_full_suite()
        regressions = []
        
        for r in current.results:
            key = r.operation + "_" + r.algorithm
            if key in self.baseline["results"]:
                baseline_time = self.baseline["results"][key]
                current_time = r.mean_time_ms
                
                if baseline_time > 0:
                    percent_change = ((current_time - baseline_time) / baseline_time) * 100
                    
                    if percent_change > threshold_percent:
                        regressions.append({
                            "operation": r.operation,
                            "algorithm": r.algorithm,
                            "baseline_ms": baseline_time,
                            "current_ms": current_time,
                            "percent_slower": percent_change,
                            "severity": "HIGH" if percent_change > 50 else "MEDIUM",
                        })
        
        self.history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "regressions": regressions,
        })
        
        return regressions
    
    def get_performance_trend(self, operation: str, algorithm: str) -> Dict[str, Any]:
        """Get performance trend over time"""
        trend = {
            "operation": operation,
            "algorithm": algorithm,
            "data_points": [],
        }
        
        # In production, load from database
        return trend