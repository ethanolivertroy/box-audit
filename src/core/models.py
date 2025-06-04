"""Data models for compliance findings"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from enum import Enum


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStatus(Enum):
    """Compliance check status"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


@dataclass
class CIAImpact:
    """CIA Triad Impact Assessment"""
    confidentiality: str  # high, medium, low
    integrity: str        # high, medium, low
    availability: str     # high, medium, low
    
    def overall_impact(self) -> str:
        """Calculate overall impact based on highest individual impact"""
        impacts = [self.confidentiality, self.integrity, self.availability]
        if 'high' in impacts:
            return 'high'
        elif 'medium' in impacts:
            return 'medium'
        return 'low'


@dataclass
class Finding:
    """Security finding from compliance check"""
    control_id: str
    control_title: str
    check_name: str
    status: ComplianceStatus
    severity: Severity
    description: str
    evidence: Dict
    remediation: str
    cia_impact: CIAImpact
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict:
        """Convert finding to dictionary for reporting"""
        return {
            'control_id': self.control_id,
            'control_title': self.control_title,
            'check_name': self.check_name,
            'status': self.status.value,
            'severity': self.severity.value,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cia_impact': {
                'confidentiality': self.cia_impact.confidentiality,
                'integrity': self.cia_impact.integrity,
                'availability': self.cia_impact.availability,
                'overall': self.cia_impact.overall_impact()
            },
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ComplianceReport:
    """Overall compliance report"""
    enterprise_id: str
    enterprise_name: str
    scan_timestamp: datetime
    findings: List[Finding]
    summary: Dict[str, int] = field(default_factory=dict)
    
    def calculate_summary(self):
        """Calculate summary statistics"""
        self.summary = {
            'total_checks': len(self.findings),
            'compliant': len([f for f in self.findings if f.status == ComplianceStatus.COMPLIANT]),
            'non_compliant': len([f for f in self.findings if f.status == ComplianceStatus.NON_COMPLIANT]),
            'partial': len([f for f in self.findings if f.status == ComplianceStatus.PARTIAL]),
            'critical_findings': len([f for f in self.findings if f.severity == Severity.CRITICAL]),
            'high_findings': len([f for f in self.findings if f.severity == Severity.HIGH]),
            'compliance_score': 0
        }
        
        if self.summary['total_checks'] > 0:
            self.summary['compliance_score'] = round(
                (self.summary['compliant'] / self.summary['total_checks']) * 100, 2
            )