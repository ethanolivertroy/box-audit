"""Audit and Accountability (AU) family compliance checks"""

import logging
from typing import List, Dict
from datetime import datetime, timedelta

from ..core.api_client import BoxAPIClient
from ..core.models import Finding, Severity, ComplianceStatus, CIAImpact

logger = logging.getLogger(__name__)


class AuditAccountabilityChecker:
    """Checks for NIST 800-53 Audit and Accountability family"""
    
    def __init__(self, api_client: BoxAPIClient):
        self.api = api_client
        self.findings = []
        
    def run_all_checks(self) -> List[Finding]:
        """Run all audit and accountability checks"""
        self.findings = []
        
        checks = [
            self.check_audit_logging,
            self.check_admin_activity_monitoring,
            self.check_event_retention,
            self.check_security_events,
            self.check_audit_log_access,
            self.check_time_stamps
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {e}")
                self.findings.append(Finding(
                    control_id="AU-ERR",
                    control_title="Audit Check Error",
                    check_name=check.__name__,
                    status=ComplianceStatus.ERROR,
                    severity=Severity.MEDIUM,
                    description=f"Failed to execute check: {str(e)}",
                    evidence={"error": str(e)},
                    remediation="Investigate and resolve the error",
                    cia_impact=CIAImpact("medium", "high", "low")
                ))
                
        return self.findings
        
    def check_audit_logging(self):
        """AU-2: Check if audit logging is properly configured"""
        logger.info("Checking audit logging configuration...")
        
        # Try to fetch recent events to verify logging is enabled
        try:
            recent_events = self.api.get_events(
                created_after=(datetime.now() - timedelta(hours=1)).isoformat()
            )
            
            if len(recent_events) == 0:
                self.findings.append(Finding(
                    control_id="AU-2",
                    control_title="Audit Events",
                    check_name="Audit Logging Status",
                    status=ComplianceStatus.NON_COMPLIANT,
                    severity=Severity.CRITICAL,
                    description="No audit events found in the last hour. Audit logging may be disabled.",
                    evidence={'recent_events_count': 0},
                    remediation="Enable enterprise event logging in Box Admin Console",
                    cia_impact=CIAImpact("medium", "high", "low")
                ))
            else:
                # Check event types being logged
                event_types = set(e['type'] for e in recent_events)
                
                # Critical events that should be logged
                critical_events = {
                    'LOGIN', 'FAILED_LOGIN', 'ADMIN_LOGIN',
                    'DELETE_USER', 'ADD_USER', 'EDIT_USER',
                    'CHANGE_ADMIN_ROLE', 'CONTENT_ACCESS',
                    'DOWNLOAD', 'DELETE', 'UPLOAD'
                }
                
                missing_events = critical_events - event_types
                
                if missing_events:
                    self.findings.append(Finding(
                        control_id="AU-2",
                        control_title="Audit Events",
                        check_name="Audit Event Coverage",
                        status=ComplianceStatus.PARTIAL,
                        severity=Severity.MEDIUM,
                        description=f"Some critical event types not captured in recent logs",
                        evidence={
                            'captured_event_types': list(event_types),
                            'missing_critical_events': list(missing_events)
                        },
                        remediation="Review and enable all security-relevant event types in audit configuration",
                        cia_impact=CIAImpact("medium", "high", "low")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="AU-2",
                        control_title="Audit Events",
                        check_name="Audit Logging Status",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description=f"Audit logging is enabled. Found {len(recent_events)} events in last hour.",
                        evidence={
                            'recent_events_count': len(recent_events),
                            'event_types': list(event_types)[:10]
                        },
                        remediation="Continue monitoring audit log configuration",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
                    
        except Exception as e:
            logger.error(f"Could not check audit events: {e}")
            self.findings.append(Finding(
                control_id="AU-2",
                control_title="Audit Events",
                check_name="Audit Logging Status",
                status=ComplianceStatus.ERROR,
                severity=Severity.HIGH,
                description="Unable to retrieve audit events. May lack permissions.",
                evidence={'error': str(e)},
                remediation="Ensure application has permission to read enterprise events",
                cia_impact=CIAImpact("high", "high", "low")
            ))
            
    def check_admin_activity_monitoring(self):
        """AU-6: Check monitoring of administrative actions"""
        logger.info("Checking admin activity monitoring...")
        
        # Look for admin events in the last 7 days
        seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
        
        admin_event_types = [
            'ADMIN_LOGIN', 'CHANGE_ADMIN_ROLE', 'DELETE_USER',
            'ADD_USER', 'EDIT_USER', 'GROUP_ADD_USER', 'GROUP_REMOVE_USER',
            'CHANGE_FOLDER_PERMISSION', 'SHIELD_ALERT'
        ]
        
        try:
            admin_events = self.api.get_events(
                event_types=admin_event_types,
                created_after=seven_days_ago
            )
            
            if not admin_events:
                self.findings.append(Finding(
                    control_id="AU-6",
                    control_title="Audit Review, Analysis, and Reporting",
                    check_name="Admin Activity Monitoring",
                    status=ComplianceStatus.NON_COMPLIANT,
                    severity=Severity.HIGH,
                    description="No administrative events captured in the last 7 days",
                    evidence={'admin_events_count': 0},
                    remediation="Enable logging for administrative actions and ensure proper permissions",
                    cia_impact=CIAImpact("high", "high", "medium")
                ))
            else:
                # Check frequency of admin actions
                admin_by_user = {}
                for event in admin_events:
                    user = event.get('created_by', 'unknown')
                    admin_by_user[user] = admin_by_user.get(user, 0) + 1
                
                # Flag users with excessive admin actions
                suspicious_admins = {u: c for u, c in admin_by_user.items() if c > 100}
                
                if suspicious_admins:
                    self.findings.append(Finding(
                        control_id="AU-6",
                        control_title="Audit Review, Analysis, and Reporting",
                        check_name="Excessive Admin Activity",
                        status=ComplianceStatus.PARTIAL,
                        severity=Severity.MEDIUM,
                        description=f"Detected users with high volume of admin actions",
                        evidence={
                            'total_admin_events': len(admin_events),
                            'suspicious_admins': suspicious_admins
                        },
                        remediation="Review admin activity for anomalies and potential automation opportunities",
                        cia_impact=CIAImpact("medium", "high", "low")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="AU-6",
                        control_title="Audit Review, Analysis, and Reporting",
                        check_name="Admin Activity Monitoring",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description=f"Admin activities are being logged. {len(admin_events)} events in last 7 days.",
                        evidence={
                            'admin_events_count': len(admin_events),
                            'admin_users': list(admin_by_user.keys())[:5]
                        },
                        remediation="Continue monitoring admin activities",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
                    
        except Exception as e:
            logger.error(f"Could not check admin events: {e}")
            
    def check_event_retention(self):
        """AU-11: Check audit log retention policies"""
        logger.info("Checking event retention...")
        
        # Try to get events from different time periods to infer retention
        retention_checks = [
            (30, "30 days"),
            (90, "90 days"),
            (180, "180 days"),
            (365, "1 year")
        ]
        
        retention_status = {}
        
        for days, period in retention_checks:
            try:
                check_date = (datetime.now() - timedelta(days=days)).isoformat()
                old_events = self.api.get_events(
                    created_after=check_date,
                    event_types=['LOGIN']  # Common event type
                )
                retention_status[period] = len(old_events) > 0
            except Exception as e:
                retention_status[period] = False
                logger.warning(f"Could not check {period} retention: {e}")
        
        # Determine retention period
        if retention_status.get("1 year", False):
            actual_retention = "1 year or more"
            status = ComplianceStatus.COMPLIANT
            severity = Severity.INFO
        elif retention_status.get("180 days", False):
            actual_retention = "180-365 days"
            status = ComplianceStatus.PARTIAL
            severity = Severity.MEDIUM
        elif retention_status.get("90 days", False):
            actual_retention = "90-180 days"
            status = ComplianceStatus.NON_COMPLIANT
            severity = Severity.HIGH
        else:
            actual_retention = "Less than 90 days"
            status = ComplianceStatus.NON_COMPLIANT
            severity = Severity.CRITICAL
        
        self.findings.append(Finding(
            control_id="AU-11",
            control_title="Audit Record Retention",
            check_name="Event Log Retention",
            status=status,
            severity=severity,
            description=f"Audit logs are retained for {actual_retention}",
            evidence={'retention_checks': retention_status},
            remediation="Configure audit log retention for at least 1 year to meet FedRAMP requirements",
            cia_impact=CIAImpact("low", "high", "low")
        ))
        
    def check_security_events(self):
        """AU-5: Check response to audit processing failures"""
        logger.info("Checking security event alerting...")
        
        # Look for security-related events
        security_events = ['FAILED_LOGIN', 'ANOMALY_DETECTION', 'SHIELD_ALERT', 
                          'SUSPICIOUS_LOCATION', 'SUSPICIOUS_SESSION']
        
        try:
            recent_security = self.api.get_events(
                event_types=security_events,
                created_after=(datetime.now() - timedelta(days=1)).isoformat()
            )
            
            # Check if any critical security events occurred
            if recent_security:
                event_summary = {}
                for event in recent_security:
                    event_type = event['type']
                    event_summary[event_type] = event_summary.get(event_type, 0) + 1
                
                self.findings.append(Finding(
                    control_id="AU-5",
                    control_title="Response to Audit Processing Failures",
                    check_name="Security Event Detection",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.MEDIUM,
                    description=f"Found {len(recent_security)} security events in last 24 hours",
                    evidence={
                        'security_events_count': len(recent_security),
                        'event_summary': event_summary
                    },
                    remediation="Ensure security events trigger appropriate alerts and response procedures",
                    cia_impact=CIAImpact("high", "high", "medium")
                ))
            else:
                self.findings.append(Finding(
                    control_id="AU-5",
                    control_title="Response to Audit Processing Failures",
                    check_name="Security Event Detection",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description="No critical security events detected in last 24 hours",
                    evidence={'security_events_count': 0},
                    remediation="Ensure alerting is configured for security events",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.error(f"Could not check security events: {e}")
            
    def check_audit_log_access(self):
        """AU-9: Check protection of audit information"""
        logger.info("Checking audit log access controls...")
        
        # Check who has accessed audit logs recently
        audit_access_events = ['VIEW_AUDIT_LOG', 'DOWNLOAD_AUDIT_LOG', 'EXPORT_AUDIT_LOG']
        
        try:
            audit_accesses = self.api.get_events(
                event_types=audit_access_events,
                created_after=(datetime.now() - timedelta(days=30)).isoformat()
            )
            
            if audit_accesses:
                # Count unique users accessing audit logs
                audit_users = set(e.get('created_by', 'unknown') for e in audit_accesses)
                
                self.findings.append(Finding(
                    control_id="AU-9",
                    control_title="Protection of Audit Information",
                    check_name="Audit Log Access",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.MEDIUM,
                    description=f"{len(audit_users)} users accessed audit logs in last 30 days",
                    evidence={
                        'audit_access_count': len(audit_accesses),
                        'unique_users': list(audit_users)
                    },
                    remediation="Review and restrict audit log access to authorized security personnel only",
                    cia_impact=CIAImpact("high", "high", "low")
                ))
            else:
                # No audit access events might mean limited logging
                self.findings.append(Finding(
                    control_id="AU-9",
                    control_title="Protection of Audit Information",
                    check_name="Audit Log Access",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.LOW,
                    description="No audit log access events found. Access may not be logged.",
                    evidence={'audit_access_events': 0},
                    remediation="Enable logging for audit log access and ensure restricted access",
                    cia_impact=CIAImpact("medium", "high", "low")
                ))
                
        except Exception as e:
            logger.warning(f"Could not check audit log access: {e}")
            
    def check_time_stamps(self):
        """AU-8: Check time stamp accuracy"""
        logger.info("Checking time stamp configuration...")
        
        # Get recent events and check time consistency
        try:
            recent_events = self.api.get_events(
                created_after=(datetime.now() - timedelta(minutes=30)).isoformat()
            )
            
            if recent_events:
                # Check if timestamps are in expected format and reasonable
                current_time = datetime.now()
                time_issues = []
                
                for event in recent_events[:10]:  # Check first 10 events
                    try:
                        event_time = datetime.fromisoformat(
                            event['created_at'].replace('Z', '+00:00')
                        )
                        # Check if event time is in the future
                        if event_time.replace(tzinfo=None) > current_time:
                            time_issues.append(f"Future timestamp: {event['created_at']}")
                    except Exception as e:
                        time_issues.append(f"Invalid timestamp format: {event['created_at']}")
                
                if time_issues:
                    self.findings.append(Finding(
                        control_id="AU-8",
                        control_title="Time Stamps",
                        check_name="Time Stamp Accuracy",
                        status=ComplianceStatus.NON_COMPLIANT,
                        severity=Severity.HIGH,
                        description="Time stamp issues detected in audit logs",
                        evidence={'issues': time_issues},
                        remediation="Ensure all systems use synchronized NTP time sources",
                        cia_impact=CIAImpact("low", "high", "low")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="AU-8",
                        control_title="Time Stamps",
                        check_name="Time Stamp Accuracy",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description="Time stamps appear to be accurate and properly formatted",
                        evidence={'sample_timestamps': [e['created_at'] for e in recent_events[:3]]},
                        remediation="Continue using synchronized time sources",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
                    
        except Exception as e:
            logger.error(f"Could not check time stamps: {e}")