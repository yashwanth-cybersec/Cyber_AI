#!/usr/bin/env python3
"""
Module: HNDL Risk Assessment
File: hndl_risk_assessment.py
Purpose: Quantify Harvest Now, Decrypt Later attack risks
Calculates: Risk scores, quantum threat timelines, mitigation priorities
"""

import json
import math
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from .crypto_engine import HybridKeyPair
from .crypto_agility import AlgorithmRegistry, AlgorithmCategory, AlgorithmStatus
from .logging_config import get_logger

logger = get_logger(__name__)

# ============================================
# RISK MODELS
# ============================================

class DataSensitivity(Enum):
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4
    CRITICAL = 5

class QuantumReadiness(Enum):
    VULNERABLE = 1       # Classical crypto only
    AWARE = 2            # Planning migration
    MIGRATING = 3        # Actively migrating
    HYBRID = 4           # Hybrid classical + PQC
    POST_QUANTUM = 5     # Pure PQC

@dataclass
class DataAsset:
    """Represents a data asset for risk assessment"""
    asset_id: str
    name: str
    sensitivity: DataSensitivity
    retention_period_days: int
    encryption_algorithm: str
    signature_algorithm: str
    created_at: datetime
    estimated_value_usd: float
    regulatory_requirements: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ThreatModel:
    """Quantum threat model parameters"""
    quantum_computer_qubits: int = 100
    qubit_growth_rate: float = 2.0  # Doubling per year
    error_correction_overhead: int = 1000
    shor_algorithm_efficiency: float = 0.7
    grover_algorithm_efficiency: float = 0.9
    
    def years_until_breaks(self, algorithm: str) -> Optional[float]:
        """Estimate years until quantum computer breaks algorithm"""
        algorithm_info = AlgorithmRegistry.ALGORITHMS.get(algorithm)
        if not algorithm_info:
            return None
        
        if algorithm_info.is_post_quantum:
            # PQC algorithms resistant to known quantum attacks
            return float('inf')
        
        security_bits = algorithm_info.security_level
        
        # Estimate required qubits
        if algorithm.startswith("RSA"):
            required_qubits = (security_bits * 2) * self.error_correction_overhead
        elif algorithm.startswith("ECDSA") or algorithm == "X25519":
            required_qubits = (security_bits * 6) * self.error_correction_overhead
        else:
            required_qubits = (security_bits * 4) * self.error_correction_overhead
        
        # Calculate years
        current_qubits = self.quantum_computer_qubits
        if required_qubits <= current_qubits:
            return 0.0
        
        doublings_needed = math.log2(required_qubits / current_qubits)
        years = doublings_needed / self.qubit_growth_rate
        
        return years * self.shor_algorithm_efficiency

# ============================================
# RISK CALCULATOR
# ============================================

class HNDLRiskCalculator:
    """Calculate HNDL attack risks for data assets"""
    
    def __init__(self, threat_model: ThreatModel = None):
        self.threat_model = threat_model or ThreatModel()
        
    def calculate_asset_risk(self, asset: DataAsset) -> Dict[str, Any]:
        """Calculate comprehensive risk score for a data asset"""
        # Base risk from sensitivity
        sensitivity_score = asset.sensitivity.value * 20  # 20-100
        
        # Encryption risk
        encryption_risk = self._calculate_encryption_risk(
            asset.encryption_algorithm,
            asset.retention_period_days,
        )
        
        # Signature risk
        signature_risk = self._calculate_signature_risk(
            asset.signature_algorithm,
            asset.retention_period_days,
        )
        
        # Regulatory risk
        regulatory_risk = len(asset.regulatory_requirements) * 10
        
        # Time-based risk (data becomes more valuable to attackers over time)
        age_days = (datetime.utcnow() - asset.created_at).days
        time_risk = min(age_days / 365 * 20, 30)
        
        # Combined risk score
        total_risk = (
            sensitivity_score * 0.3 +
            encryption_risk * 0.3 +
            signature_risk * 0.2 +
            regulatory_risk * 0.1 +
            time_risk * 0.1
        )
        
        # Risk level
        if total_risk >= 80:
            risk_level = "CRITICAL"
        elif total_risk >= 60:
            risk_level = "HIGH"
        elif total_risk >= 40:
            risk_level = "MEDIUM"
        elif total_risk >= 20:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"
        
        return {
            "asset_id": asset.asset_id,
            "risk_score": round(total_risk, 2),
            "risk_level": risk_level,
            "components": {
                "sensitivity": round(sensitivity_score, 2),
                "encryption": round(encryption_risk, 2),
                "signature": round(signature_risk, 2),
                "regulatory": round(regulatory_risk, 2),
                "time_based": round(time_risk, 2),
            },
            "quantum_vulnerability": self._assess_quantum_vulnerability(asset),
            "mitigation_priority": self._calculate_priority(asset, total_risk),
            "estimated_breach_cost": asset.estimated_value_usd * (total_risk / 100),
        }
    
    def _calculate_encryption_risk(self, algorithm: str, retention_days: int) -> float:
        """Calculate encryption-related HNDL risk"""
        years_until_break = self.threat_model.years_until_breaks(algorithm)
        
        if years_until_break is None:
            return 50.0  # Unknown algorithm
        
        if years_until_break == float('inf'):
            return 5.0  # Post-quantum safe
        
        retention_years = retention_days / 365
        
        if retention_years > years_until_break:
            # Data will outlive encryption
            risk = 80 + (retention_years - years_until_break) * 10
            return min(risk, 100)
        else:
            # Encryption will outlive data
            risk = max(20, 80 - (years_until_break - retention_years) * 20)
            return risk
    
    def _calculate_signature_risk(self, algorithm: str, retention_days: int) -> float:
        """Calculate signature-related HNDL risk"""
        # Similar to encryption but with different weights
        years_until_break = self.threat_model.years_until_breaks(algorithm)
        
        if years_until_break is None:
            return 40.0
        
        if years_until_break == float('inf'):
            return 5.0
        
        retention_years = retention_days / 365
        
        if retention_years > years_until_break:
            risk = 70 + (retention_years - years_until_break) * 10
            return min(risk, 100)
        else:
            risk = max(15, 70 - (years_until_break - retention_years) * 15)
            return risk
    
    def _assess_quantum_vulnerability(self, asset: DataAsset) -> Dict[str, Any]:
        """Assess quantum vulnerability of the asset"""
        enc_years = self.threat_model.years_until_breaks(asset.encryption_algorithm)
        sig_years = self.threat_model.years_until_breaks(asset.signature_algorithm)
        
        if enc_years == float('inf') and sig_years == float('inf'):
            readiness = QuantumReadiness.POST_QUANTUM
        elif AlgorithmRegistry.ALGORITHMS.get(asset.encryption_algorithm, {}).get('is_hybrid_capable', False):
            readiness = QuantumReadiness.HYBRID
        elif enc_years and enc_years > 10:
            readiness = QuantumReadiness.AWARE
        else:
            readiness = QuantumReadiness.VULNERABLE
        
        return {
            "readiness": readiness.name,
            "encryption_years_until_break": enc_years if enc_years != float('inf') else None,
            "signature_years_until_break": sig_years if sig_years != float('inf') else None,
            "migration_urgency": "IMMEDIATE" if readiness == QuantumReadiness.VULNERABLE else "PLANNED" if readiness == QuantumReadiness.AWARE else "LOW",
        }
    
    def _calculate_priority(self, asset: DataAsset, risk_score: float) -> int:
        """Calculate mitigation priority (1-10)"""
        priority = int(risk_score / 10)
        
        if asset.sensitivity in [DataSensitivity.CRITICAL, DataSensitivity.RESTRICTED]:
            priority = min(priority + 2, 10)
        
        if asset.retention_period_days > 365 * 5:  # >5 years
            priority = min(priority + 1, 10)
        
        return priority
    
    def calculate_portfolio_risk(self, assets: List[DataAsset]) -> Dict[str, Any]:
        """Calculate aggregate risk across portfolio"""
        if not assets:
            return {"total_assets": 0, "aggregate_risk": 0}
        
        asset_risks = [self.calculate_asset_risk(a) for a in assets]
        
        total_value = sum(a.estimated_value_usd for a in assets)
        weighted_risk = sum(
            r["risk_score"] * a.estimated_value_usd / total_value
            for r, a in zip(asset_risks, assets)
        ) if total_value > 0 else sum(r["risk_score"] for r in asset_risks) / len(asset_risks)
        
        risk_levels = {}
        for r in asset_risks:
            level = r["risk_level"]
            risk_levels[level] = risk_levels.get(level, 0) + 1
        
        return {
            "total_assets": len(assets),
            "total_value_usd": total_value,
            "weighted_risk_score": round(weighted_risk, 2),
            "risk_level_distribution": risk_levels,
            "critical_assets": [r for r in asset_risks if r["risk_level"] == "CRITICAL"],
            "high_risk_assets": [r for r in asset_risks if r["risk_level"] == "HIGH"],
            "recommendations": self._generate_portfolio_recommendations(asset_risks),
        }
    
    def _generate_portfolio_recommendations(self, asset_risks: List[Dict]) -> List[str]:
        """Generate portfolio-wide recommendations"""
        recommendations = []
        
        critical_count = sum(1 for r in asset_risks if r["risk_level"] == "CRITICAL")
        vulnerable_count = sum(
            1 for r in asset_risks
            if r.get("quantum_vulnerability", {}).get("readiness") == "VULNERABLE"
        )
        
        if critical_count > 0:
            recommendations.append(
                f"IMMEDIATE ACTION: {critical_count} critical-risk assets require migration"
            )
        
        if vulnerable_count > 0:
            recommendations.append(
                f"Migrate {vulnerable_count} quantum-vulnerable assets to hybrid encryption"
            )
        
        if any(r["risk_score"] > 60 for r in asset_risks):
            recommendations.append(
                "Implement crypto-agility to enable rapid algorithm rotation"
            )
        
        return recommendations

# ============================================
# TIMELINE PROJECTOR
# ============================================

class QuantumTimelineProjector:
    """Project quantum threat timelines"""
    
    def __init__(self, threat_model: ThreatModel = None):
        self.threat_model = threat_model or ThreatModel()
        self.milestones = {
            "RSA-2048_broken": "RSA-2048 broken by quantum computer",
            "ECDSA-256_broken": "ECDSA-256 broken by quantum computer",
            "quantum_supremacy": "Quantum supremacy for crypto achieved",
            "pqc_standardization": "NIST PQC standards finalized",
        }
    
    def project_timeline(self) -> Dict[str, Any]:
        """Project quantum threat timeline"""
        timeline = []
        
        rsa_2048_years = self.threat_model.years_until_breaks("RSA-2048")
        ecdsa_256_years = self.threat_model.years_until_breaks("ECDSA-P256")
        
        now = datetime.utcnow()
        
        if rsa_2048_years is not None and rsa_2048_years != float('inf'):
            timeline.append({
                "date": (now + timedelta(days=int(rsa_2048_years * 365))).isoformat(),
                "event": self.milestones["RSA-2048_broken"],
                "confidence": min(rsa_2048_years / 20, 1.0),
            })
        
        if ecdsa_256_years is not None and ecdsa_256_years != float('inf'):
            timeline.append({
                "date": (now + timedelta(days=int(ecdsa_256_years * 365))).isoformat(),
                "event": self.milestones["ECDSA-256_broken"],
                "confidence": min(ecdsa_256_years / 15, 1.0),
            })
        
        # Sort by date
        timeline.sort(key=lambda x: x["date"])
        
        return {
            "timeline": timeline,
            "current_qubit_estimate": self.threat_model.quantum_computer_qubits,
            "qubit_growth_rate": self.threat_model.qubit_growth_rate,
            "recommended_migration_window": self._calculate_migration_window(),
        }
    
    def _calculate_migration_window(self) -> Dict[str, Any]:
        """Calculate recommended migration window"""
        rsa_years = self.threat_model.years_until_breaks("RSA-2048")
        
        if rsa_years is None or rsa_years == float('inf'):
            return {"urgency": "LOW", "years_remaining": None}
        
        if rsa_years < 2:
            urgency = "CRITICAL"
            window = "IMMEDIATE"
        elif rsa_years < 5:
            urgency = "HIGH"
            window = "1-2 years"
        elif rsa_years < 10:
            urgency = "MEDIUM"
            window = "2-5 years"
        else:
            urgency = "LOW"
            window = "5+ years"
        
        return {
            "urgency": urgency,
            "years_remaining": round(rsa_years, 1),
            "recommended_window": window,
            "target_algorithm": "ML-KEM-768+X25519",
        }

# ============================================
# COMPLIANCE MAPPER
# ============================================

class ComplianceMapper:
    """Map HNDL risks to compliance requirements"""
    
    COMPLIANCE_FRAMEWORKS = {
        "NIST_SP_800-175B": {
            "requires_pqc": True,
            "transition_period": "2025-2030",
            "key_requirements": ["crypto_agility", "hybrid_mode"],
        },
        "FIPS_140-3": {
            "requires_pqc": False,
            "pqc_allowed": True,
            "hybrid_mode": "transitional",
        },
        "GDPR": {
            "requires_encryption": True,
            "state_of_art": True,
        },
        "HIPAA": {
            "requires_encryption": True,
            "addressable": True,
        },
        "PCI_DSS": {
            "requires_encryption": True,
            "strong_cryptography": True,
        },
        "CMMC": {
            "level_3_requires": ["FIPS_validated", "quantum_awareness"],
        },
    }
    
    def assess_compliance(self, asset: DataAsset) -> Dict[str, Any]:
        """Assess compliance status for an asset"""
        results = {}
        
        for framework, requirements in self.COMPLIANCE_FRAMEWORKS.items():
            status = self._check_framework_compliance(asset, framework, requirements)
            results[framework] = status
        
        return results
    
    def _check_framework_compliance(
        self,
        asset: DataAsset,
        framework: str,
        requirements: Dict,
    ) -> Dict[str, Any]:
        """Check compliance with specific framework"""
        compliant = True
        gaps = []
        
        if requirements.get("requires_pqc", False):
            if not AlgorithmRegistry.ALGORITHMS.get(asset.encryption_algorithm, {}).get("is_post_quantum", False):
                compliant = False
                gaps.append("encryption_not_pqc")
        
        if requirements.get("hybrid_mode") == "required":
            if not AlgorithmRegistry.ALGORITHMS.get(asset.encryption_algorithm, {}).get("is_hybrid_capable", False):
                compliant = False
                gaps.append("not_hybrid_capable")
        
        return {
            "framework": framework,
            "compliant": compliant,
            "gaps": gaps,
            "recommendation": self._get_compliance_recommendation(framework, gaps),
        }
    
    def _get_compliance_recommendation(self, framework: str, gaps: List[str]) -> str:
        """Get compliance recommendation"""
        if not gaps:
            return "Compliant"
        
        if "encryption_not_pqc" in gaps:
            return f"Migrate to post-quantum encryption for {framework} compliance"
        elif "not_hybrid_capable" in gaps:
            return f"Enable hybrid mode for {framework} compliance"
        
        return "Review requirements"

# ============================================
# RISK REPORT GENERATOR
# ============================================

class RiskReportGenerator:
    """Generate comprehensive HNDL risk reports"""
    
    def __init__(self):
        self.calculator = HNDLRiskCalculator()
        self.projector = QuantumTimelineProjector()
        self.compliance = ComplianceMapper()
    
    def generate_full_report(self, assets: List[DataAsset]) -> Dict[str, Any]:
        """Generate full risk assessment report"""
        portfolio_risk = self.calculator.calculate_portfolio_risk(assets)
        timeline = self.projector.project_timeline()
        
        asset_details = []
        for asset in assets:
            asset_risk = self.calculator.calculate_asset_risk(asset)
            asset_compliance = self.compliance.assess_compliance(asset)
            asset_details.append({
                **asset_risk,
                "compliance": asset_compliance,
            })
        
        return {
            "report_id": f"HNDL-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_assets": portfolio_risk["total_assets"],
                "total_value_usd": portfolio_risk["total_value_usd"],
                "weighted_risk_score": portfolio_risk["weighted_risk_score"],
                "risk_level_distribution": portfolio_risk["risk_level_distribution"],
            },
            "quantum_timeline": timeline,
            "assets": asset_details,
            "recommendations": portfolio_risk["recommendations"],
            "executive_summary": self._generate_executive_summary(portfolio_risk, timeline),
        }
    
    def _generate_executive_summary(self, portfolio: Dict, timeline: Dict) -> str:
        """Generate executive summary"""
        risk_score = portfolio["weighted_risk_score"]
        
        if risk_score >= 70:
            urgency = "CRITICAL - Immediate action required"
        elif risk_score >= 50:
            urgency = "HIGH - Action required within 3 months"
        elif risk_score >= 30:
            urgency = "MEDIUM - Action required within 12 months"
        else:
            urgency = "LOW - Monitor and plan"
        
        migration = timeline.get("recommended_migration_window", {})
        
        return f"""
HNDL RISK ASSESSMENT EXECUTIVE SUMMARY
======================================
Overall Risk Score: {risk_score:.1f}/100
Risk Level: {urgency}
Total Assets Assessed: {portfolio['total_assets']}
Total Asset Value: ${portfolio['total_value_usd']:,.2f}

Quantum Threat Timeline:
- Migration Urgency: {migration.get('urgency', 'Unknown')}
- Recommended Window: {migration.get('recommended_window', 'Unknown')}
- Target Algorithm: {migration.get('target_algorithm', 'Hybrid PQC')}

Critical Assets Requiring Immediate Attention:
{len(portfolio.get('critical_assets', []))} assets at CRITICAL risk level

Key Recommendations:
{chr(10).join(f'- {r}' for r in portfolio.get('recommendations', []))}
"""