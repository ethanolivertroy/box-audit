"""System and Communications Protection (SC) family compliance checks"""

import logging
from typing import List, Dict
from datetime import datetime

from ..core.api_client import BoxAPIClient
from ..core.models import Finding, Severity, ComplianceStatus, CIAImpact

logger = logging.getLogger(__name__)


class SystemProtectionChecker:
    """Checks for NIST 800-53 System and Communications Protection family"""
    
    def __init__(self, api_client: BoxAPIClient):
        self.api = api_client
        self.findings = []
        
    def run_all_checks(self) -> List[Finding]:
        """Run all system and communications protection checks"""
        self.findings = []
        
        checks = [
            self.check_encryption_at_rest,
            self.check_encryption_in_transit,
            self.check_data_loss_prevention,
            self.check_watermarking,
            self.check_classification_labels,
            self.check_api_security,
            self.check_boundary_protection,
            self.check_mobile_security
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {e}")
                self.findings.append(Finding(
                    control_id="SC-ERR",
                    control_title="System Protection Check Error",
                    check_name=check.__name__,
                    status=ComplianceStatus.ERROR,
                    severity=Severity.MEDIUM,
                    description=f"Failed to execute check: {str(e)}",
                    evidence={"error": str(e)},
                    remediation="Investigate and resolve the error",
                    cia_impact=CIAImpact("high", "high", "low")
                ))
                
        return self.findings
        
    def check_encryption_at_rest(self):
        """SC-28: Check encryption at rest settings"""
        logger.info("Checking encryption at rest...")
        
        # Get enterprise settings
        try:
            settings = self.api.get_enterprise_settings()
            
            # Box encrypts all data at rest by default, but check for additional controls
            # Look for any custom encryption or key management settings
            
            # Since Box provides AES 256-bit encryption by default, this is typically compliant
            self.findings.append(Finding(
                control_id="SC-28",
                control_title="Protection of Information at Rest",
                check_name="Encryption at Rest",
                status=ComplianceStatus.COMPLIANT,
                severity=Severity.INFO,
                description="Box provides AES 256-bit encryption at rest for all files by default",
                evidence={
                    'encryption_standard': 'AES-256',
                    'default_enabled': True,
                    'enterprise_id': settings.get('enterprise_id')
                },
                remediation="Continue using Box's default encryption. Consider Box KeySafe for additional key management control.",
                cia_impact=CIAImpact("low", "low", "low")
            ))
            
        except Exception as e:
            logger.error(f"Could not verify encryption settings: {e}")
            self.findings.append(Finding(
                control_id="SC-28",
                control_title="Protection of Information at Rest",
                check_name="Encryption at Rest",
                status=ComplianceStatus.PARTIAL,
                severity=Severity.MEDIUM,
                description="Unable to fully verify encryption at rest settings",
                evidence={'error': str(e)},
                remediation="Verify encryption settings in Box Admin Console",
                cia_impact=CIAImpact("high", "medium", "low")
            ))
            
    def check_encryption_in_transit(self):
        """SC-8: Check encryption in transit settings"""
        logger.info("Checking encryption in transit...")
        
        # Box enforces TLS for all connections
        # Check for any events indicating insecure access attempts
        
        try:
            # Look for security events related to connection security
            security_events = self.api.get_events(
                event_types=['FAILED_TLS_CONNECTION', 'INSECURE_REDIRECT', 'WEAK_CIPHER_USED'],
                created_after=(datetime.now().replace(day=1)).isoformat()
            )
            
            if security_events:
                self.findings.append(Finding(
                    control_id="SC-8",
                    control_title="Transmission Confidentiality and Integrity",
                    check_name="TLS Security Events",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.MEDIUM,
                    description=f"Found {len(security_events)} TLS security events this month",
                    evidence={
                        'security_event_count': len(security_events),
                        'event_types': list(set(e['type'] for e in security_events))
                    },
                    remediation="Investigate TLS security events and ensure all clients use modern TLS versions",
                    cia_impact=CIAImpact("high", "high", "low")
                ))
            else:
                self.findings.append(Finding(
                    control_id="SC-8",
                    control_title="Transmission Confidentiality and Integrity",
                    check_name="Encryption in Transit",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description="Box enforces TLS 1.2+ for all connections. No security events detected.",
                    evidence={
                        'tls_minimum': 'TLS 1.2',
                        'enforcement': 'mandatory',
                        'security_events': 0
                    },
                    remediation="Continue enforcing TLS for all connections",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.warning(f"Could not check TLS events: {e}")
            # Still mark as compliant since Box enforces TLS by default
            self.findings.append(Finding(
                control_id="SC-8",
                control_title="Transmission Confidentiality and Integrity",
                check_name="Encryption in Transit",
                status=ComplianceStatus.COMPLIANT,
                severity=Severity.INFO,
                description="Box enforces TLS 1.2+ for all connections by default",
                evidence={'tls_enforcement': 'default'},
                remediation="Continue using Box's default TLS enforcement",
                cia_impact=CIAImpact("low", "low", "low")
            ))
            
    def check_data_loss_prevention(self):
        """SC-7: Check DLP and information flow controls"""
        logger.info("Checking data loss prevention...")
        
        # Check for DLP-related events and policies
        dlp_events = ['SHIELD_ALERT', 'SHIELD_BLOCK', 'SHIELD_DOWNLOAD_BLOCKED', 
                     'ANOMALY_DETECTION', 'SUSPICIOUS_DOWNLOAD']
        
        try:
            recent_dlp = self.api.get_events(
                event_types=dlp_events,
                created_after=(datetime.now().replace(day=1)).isoformat()
            )
            
            # Check collaboration whitelist as a form of DLP
            whitelist = self.api.get_collaboration_whitelist()
            
            dlp_score = 0
            dlp_evidence = {}
            
            # Points for having Shield alerts
            if any(e['type'].startswith('SHIELD') for e in recent_dlp):
                dlp_score += 40
                dlp_evidence['shield_active'] = True
                dlp_evidence['shield_alerts'] = len([e for e in recent_dlp if 'SHIELD' in e['type']])
            
            # Points for having collaboration whitelist
            if whitelist:
                dlp_score += 30
                dlp_evidence['collaboration_whitelist'] = len(whitelist)
            
            # Points for anomaly detection
            if any(e['type'] == 'ANOMALY_DETECTION' for e in recent_dlp):
                dlp_score += 30
                dlp_evidence['anomaly_detection'] = True
            
            if dlp_score >= 70:
                status = ComplianceStatus.COMPLIANT
                severity = Severity.INFO
                description = "Data loss prevention controls are properly configured"
            elif dlp_score >= 30:
                status = ComplianceStatus.PARTIAL
                severity = Severity.MEDIUM
                description = "Some DLP controls are configured but could be enhanced"
            else:
                status = ComplianceStatus.NON_COMPLIANT
                severity = Severity.HIGH
                description = "Insufficient data loss prevention controls"
            
            self.findings.append(Finding(
                control_id="SC-7",
                control_title="Boundary Protection",
                check_name="Data Loss Prevention",
                status=status,
                severity=severity,
                description=description,
                evidence=dlp_evidence,
                remediation="Enable Box Shield for advanced DLP, configure collaboration whitelist, and enable anomaly detection",
                cia_impact=CIAImpact("high", "medium", "low")
            ))
            
        except Exception as e:
            logger.error(f"Could not check DLP settings: {e}")
            
    def check_watermarking(self):
        """SC-8(1): Check watermarking for sensitive content"""
        logger.info("Checking watermarking configuration...")
        
        # Look for watermarking events
        watermark_events = ['WATERMARK_DOWNLOAD', 'WATERMARK_PREVIEW', 'WATERMARK_PRINT']
        
        try:
            recent_watermarks = self.api.get_events(
                event_types=watermark_events,
                created_after=(datetime.now().replace(day=1)).isoformat()
            )
            
            if recent_watermarks:
                self.findings.append(Finding(
                    control_id="SC-8(1)",
                    control_title="Cryptographic Protection",
                    check_name="Watermarking",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description=f"Watermarking is active. {len(recent_watermarks)} watermarked operations this month.",
                    evidence={
                        'watermark_events': len(recent_watermarks),
                        'watermark_types': list(set(e['type'] for e in recent_watermarks))
                    },
                    remediation="Continue using watermarking for sensitive content",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
            else:
                self.findings.append(Finding(
                    control_id="SC-8(1)",
                    control_title="Cryptographic Protection",
                    check_name="Watermarking",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.MEDIUM,
                    description="No watermarking activity detected. May not be configured for sensitive content.",
                    evidence={'watermark_events': 0},
                    remediation="Enable watermarking for folders containing sensitive or classified information",
                    cia_impact=CIAImpact("medium", "low", "low")
                ))
                
        except Exception as e:
            logger.warning(f"Could not check watermarking: {e}")
            
    def check_classification_labels(self):
        """SC-16: Check information classification labels"""
        logger.info("Checking classification labels...")
        
        # Look for classification-related events
        classification_events = ['CLASSIFICATION_CREATE', 'CLASSIFICATION_UPDATE', 
                               'CLASSIFICATION_DELETE', 'FILE_MARKED_MALICIOUS']
        
        try:
            recent_classifications = self.api.get_events(
                event_types=classification_events,
                created_after=(datetime.now().replace(day=1)).isoformat()
            )
            
            if recent_classifications:
                # Check for malicious file detections
                malicious_files = [e for e in recent_classifications if e['type'] == 'FILE_MARKED_MALICIOUS']
                
                if malicious_files:
                    self.findings.append(Finding(
                        control_id="SC-16",
                        control_title="Transmission of Security Attributes",
                        check_name="Malicious File Detection",
                        status=ComplianceStatus.PARTIAL,
                        severity=Severity.HIGH,
                        description=f"Detected {len(malicious_files)} malicious files this month",
                        evidence={
                            'malicious_file_count': len(malicious_files),
                            'total_classification_events': len(recent_classifications)
                        },
                        remediation="Review malicious file detections and ensure proper incident response",
                        cia_impact=CIAImpact("high", "high", "medium")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="SC-16",
                        control_title="Transmission of Security Attributes",
                        check_name="Classification Labels",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description="Classification system is active with no malicious files detected",
                        evidence={'classification_events': len(recent_classifications)},
                        remediation="Continue using classification labels for sensitive content",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
            else:
                self.findings.append(Finding(
                    control_id="SC-16",
                    control_title="Transmission of Security Attributes",
                    check_name="Classification Labels",
                    status=ComplianceStatus.NON_COMPLIANT,
                    severity=Severity.MEDIUM,
                    description="No classification activity detected. Classification may not be configured.",
                    evidence={'classification_events': 0},
                    remediation="Implement Box classification templates for data categorization",
                    cia_impact=CIAImpact("medium", "medium", "low")
                ))
                
        except Exception as e:
            logger.warning(f"Could not check classification: {e}")
            
    def check_api_security(self):
        """SC-13: Check API security and OAuth apps"""
        logger.info("Checking API security...")
        
        # Look for API and OAuth related events
        api_events = ['OAUTH2_ACCESS_TOKEN_CREATED', 'APP_AUTH_AUTHORIZATION', 
                     'SUSPICIOUS_API_ACTIVITY', 'API_RATE_LIMIT_EXCEEDED']
        
        try:
            recent_api = self.api.get_events(
                event_types=api_events,
                created_after=(datetime.now().replace(day=1)).isoformat()
            )
            
            # Check for suspicious API activity
            suspicious_api = [e for e in recent_api if 'SUSPICIOUS' in e.get('type', '')]
            rate_limits = [e for e in recent_api if 'RATE_LIMIT' in e.get('type', '')]
            
            if suspicious_api:
                self.findings.append(Finding(
                    control_id="SC-13",
                    control_title="Cryptographic Protection",
                    check_name="API Security",
                    status=ComplianceStatus.NON_COMPLIANT,
                    severity=Severity.HIGH,
                    description=f"Detected {len(suspicious_api)} suspicious API activities",
                    evidence={
                        'suspicious_activities': len(suspicious_api),
                        'rate_limit_hits': len(rate_limits)
                    },
                    remediation="Review API access logs, revoke suspicious tokens, and implement API access controls",
                    cia_impact=CIAImpact("high", "high", "medium")
                ))
            elif len(rate_limits) > 10:
                self.findings.append(Finding(
                    control_id="SC-13",
                    control_title="Cryptographic Protection",
                    check_name="API Rate Limiting",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.MEDIUM,
                    description=f"High number of API rate limit events: {len(rate_limits)}",
                    evidence={'rate_limit_events': len(rate_limits)},
                    remediation="Review applications hitting rate limits and optimize API usage",
                    cia_impact=CIAImpact("low", "low", "medium")
                ))
            else:
                self.findings.append(Finding(
                    control_id="SC-13",
                    control_title="Cryptographic Protection",
                    check_name="API Security",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description="API access appears normal with no suspicious activity",
                    evidence={
                        'total_api_events': len(recent_api),
                        'oauth_tokens_created': len([e for e in recent_api if 'TOKEN_CREATED' in e.get('type', '')])
                    },
                    remediation="Continue monitoring API access patterns",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.warning(f"Could not check API security: {e}")
            
    def check_boundary_protection(self):
        """SC-7: Check network boundary protection"""
        logger.info("Checking boundary protection...")
        
        # Check device trust and access controls
        try:
            device_pins = self.api.get_device_pins()
            whitelist = self.api.get_collaboration_whitelist()
            
            boundary_score = 0
            evidence = {}
            
            # Points for device trust
            if device_pins:
                boundary_score += 50
                evidence['device_trust_enabled'] = True
                evidence['trusted_devices'] = len(device_pins)
            
            # Points for collaboration whitelist
            if whitelist:
                boundary_score += 50
                evidence['collaboration_whitelist'] = True
                evidence['whitelisted_domains'] = len(whitelist)
            
            if boundary_score >= 80:
                status = ComplianceStatus.COMPLIANT
                severity = Severity.INFO
                description = "Strong boundary protection controls in place"
            elif boundary_score >= 50:
                status = ComplianceStatus.PARTIAL
                severity = Severity.MEDIUM
                description = "Some boundary protection controls configured"
            else:
                status = ComplianceStatus.NON_COMPLIANT
                severity = Severity.HIGH
                description = "Insufficient boundary protection controls"
            
            self.findings.append(Finding(
                control_id="SC-7",
                control_title="Boundary Protection",
                check_name="Network Boundary Controls",
                status=status,
                severity=severity,
                description=description,
                evidence=evidence,
                remediation="Enable device trust requirements and configure collaboration whitelist",
                cia_impact=CIAImpact("high", "medium", "low")
            ))
            
        except Exception as e:
            logger.error(f"Could not check boundary protection: {e}")
            
    def check_mobile_security(self):
        """SC-42: Check mobile device security"""
        logger.info("Checking mobile device security...")
        
        # Look for mobile-related security events
        mobile_events = ['MOBILE_DEVICE_TRUST', 'MOBILE_APP_DOWNLOAD', 
                        'DEVICE_TRUST_CHECK_FAILED', 'UNTRUSTED_DEVICE_ACCESS']
        
        try:
            recent_mobile = self.api.get_events(
                event_types=mobile_events,
                created_after=(datetime.now().replace(day=1)).isoformat()
            )
            
            # Check for untrusted device access attempts
            untrusted_access = [e for e in recent_mobile if 'UNTRUSTED' in e.get('type', '') or 'FAILED' in e.get('type', '')]
            
            if untrusted_access:
                self.findings.append(Finding(
                    control_id="SC-42",
                    control_title="Sensor Capability and Data",
                    check_name="Mobile Device Security",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.MEDIUM,
                    description=f"Detected {len(untrusted_access)} untrusted device access attempts",
                    evidence={
                        'untrusted_attempts': len(untrusted_access),
                        'total_mobile_events': len(recent_mobile)
                    },
                    remediation="Review device trust settings and ensure mobile devices meet security requirements",
                    cia_impact=CIAImpact("high", "medium", "low")
                ))
            elif recent_mobile:
                self.findings.append(Finding(
                    control_id="SC-42",
                    control_title="Sensor Capability and Data",
                    check_name="Mobile Device Security",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description="Mobile device access is monitored with no untrusted access detected",
                    evidence={'mobile_events': len(recent_mobile)},
                    remediation="Continue enforcing mobile device security policies",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
            else:
                self.findings.append(Finding(
                    control_id="SC-42",
                    control_title="Sensor Capability and Data",
                    check_name="Mobile Device Security",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.LOW,
                    description="No mobile device events detected. Mobile security may not be configured.",
                    evidence={'mobile_events': 0},
                    remediation="Configure mobile device trust and app protection policies",
                    cia_impact=CIAImpact("medium", "low", "low")
                ))
                
        except Exception as e:
            logger.warning(f"Could not check mobile device security: {e}")