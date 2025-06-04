"""Identification and Authentication (IA) family compliance checks"""

import logging
from typing import List, Dict
from datetime import datetime, timedelta

from ..core.api_client import BoxAPIClient
from ..core.models import Finding, Severity, ComplianceStatus, CIAImpact

logger = logging.getLogger(__name__)


class IdentificationAuthChecker:
    """Checks for NIST 800-53 Identification and Authentication family"""
    
    def __init__(self, api_client: BoxAPIClient):
        self.api = api_client
        self.findings = []
        
    def run_all_checks(self) -> List[Finding]:
        """Run all identification and authentication checks"""
        self.findings = []
        
        checks = [
            self.check_mfa_enforcement,
            self.check_password_policy,
            self.check_session_controls,
            self.check_failed_login_attempts,
            self.check_sso_configuration,
            self.check_service_accounts,
            self.check_privileged_access
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {e}")
                self.findings.append(Finding(
                    control_id="IA-ERR",
                    control_title="Authentication Check Error",
                    check_name=check.__name__,
                    status=ComplianceStatus.ERROR,
                    severity=Severity.MEDIUM,
                    description=f"Failed to execute check: {str(e)}",
                    evidence={"error": str(e)},
                    remediation="Investigate and resolve the error",
                    cia_impact=CIAImpact("high", "high", "medium")
                ))
                
        return self.findings
        
    def check_mfa_enforcement(self):
        """IA-2(1): Check multi-factor authentication enforcement"""
        logger.info("Checking MFA enforcement...")
        
        # Get login settings
        login_settings = self.api.get_login_settings()
        
        # Since we might not have direct API access to MFA settings,
        # we'll check for MFA-related events
        mfa_events = ['MFA_ENABLED', 'MFA_DISABLED', 'MFA_CHALLENGE_SUCCESS', 
                     'MFA_CHALLENGE_FAIL', 'TWO_FACTOR_AUTH_ENABLE']
        
        try:
            recent_mfa = self.api.get_events(
                event_types=mfa_events,
                created_after=(datetime.now() - timedelta(days=30)).isoformat()
            )
            
            # Check if MFA is being used
            if not recent_mfa and login_settings.get('mfa_required') is not True:
                self.findings.append(Finding(
                    control_id="IA-2(1)",
                    control_title="Network Access to Privileged Accounts",
                    check_name="Multi-Factor Authentication",
                    status=ComplianceStatus.NON_COMPLIANT,
                    severity=Severity.CRITICAL,
                    description="No MFA activity detected. MFA may not be enforced.",
                    evidence={
                        'mfa_events_count': 0,
                        'login_settings': login_settings
                    },
                    remediation="Enable mandatory MFA for all users, especially administrators",
                    cia_impact=CIAImpact("high", "high", "medium")
                ))
            else:
                # Analyze MFA adoption
                mfa_success = len([e for e in recent_mfa if 'SUCCESS' in e.get('type', '')])
                mfa_fail = len([e for e in recent_mfa if 'FAIL' in e.get('type', '')])
                
                if mfa_fail > mfa_success * 0.2:  # More than 20% failure rate
                    self.findings.append(Finding(
                        control_id="IA-2(1)",
                        control_title="Network Access to Privileged Accounts",
                        check_name="MFA Challenge Failures",
                        status=ComplianceStatus.PARTIAL,
                        severity=Severity.MEDIUM,
                        description=f"High MFA failure rate detected: {mfa_fail} failures vs {mfa_success} successes",
                        evidence={
                            'mfa_success': mfa_success,
                            'mfa_failures': mfa_fail,
                            'failure_rate': mfa_fail / (mfa_success + mfa_fail) if (mfa_success + mfa_fail) > 0 else 0
                        },
                        remediation="Investigate high MFA failure rate and provide user training",
                        cia_impact=CIAImpact("medium", "medium", "low")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="IA-2(1)",
                        control_title="Network Access to Privileged Accounts",
                        check_name="Multi-Factor Authentication",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description="MFA appears to be active with acceptable success rate",
                        evidence={'mfa_events': len(recent_mfa)},
                        remediation="Continue enforcing MFA for all users",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
                    
        except Exception as e:
            logger.error(f"Could not check MFA status: {e}")
            
    def check_password_policy(self):
        """IA-5: Check password policy strength"""
        logger.info("Checking password policy...")
        
        # Look for password-related events
        password_events = ['PASSWORD_CHANGE', 'PASSWORD_RESET', 'PASSWORD_POLICY_VIOLATION']
        
        try:
            recent_password = self.api.get_events(
                event_types=password_events,
                created_after=(datetime.now() - timedelta(days=90)).isoformat()
            )
            
            # Without direct API access to password policy, we infer from events
            password_changes = [e for e in recent_password if e['type'] == 'PASSWORD_CHANGE']
            
            # Get all users to calculate password change rate
            users = self.api.get_all_users()
            
            if users:
                change_rate = len(password_changes) / len(users)
                
                if change_rate < 0.25:  # Less than 25% changed passwords in 90 days
                    self.findings.append(Finding(
                        control_id="IA-5",
                        control_title="Authenticator Management",
                        check_name="Password Rotation",
                        status=ComplianceStatus.NON_COMPLIANT,
                        severity=Severity.HIGH,
                        description=f"Low password rotation rate: only {len(password_changes)} changes for {len(users)} users in 90 days",
                        evidence={
                            'password_changes': len(password_changes),
                            'total_users': len(users),
                            'change_rate': change_rate
                        },
                        remediation="Implement and enforce 90-day password rotation policy",
                        cia_impact=CIAImpact("high", "high", "low")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="IA-5",
                        control_title="Authenticator Management",
                        check_name="Password Rotation",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description=f"Acceptable password rotation rate: {change_rate:.1%}",
                        evidence={'change_rate': change_rate},
                        remediation="Continue enforcing password rotation policy",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
                    
        except Exception as e:
            logger.error(f"Could not check password policy: {e}")
            
    def check_session_controls(self):
        """IA-11: Check re-authentication for sensitive operations"""
        logger.info("Checking session controls...")
        
        # Look for session-related events
        session_events = ['SESSION_TIMEOUT', 'SESSION_INVALIDATE', 'REAUTHENTICATION_REQUIRED']
        
        try:
            recent_sessions = self.api.get_events(
                event_types=session_events,
                created_after=(datetime.now() - timedelta(days=7)).isoformat()
            )
            
            # Check if session controls are active
            if not recent_sessions:
                self.findings.append(Finding(
                    control_id="IA-11",
                    control_title="Re-authentication",
                    check_name="Session Controls",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.MEDIUM,
                    description="No session timeout events detected. Session controls may be too permissive.",
                    evidence={'session_events': 0},
                    remediation="Configure session timeout (15-30 minutes) and require re-authentication for sensitive operations",
                    cia_impact=CIAImpact("high", "medium", "low")
                ))
            else:
                # Analyze session patterns
                timeout_events = [e for e in recent_sessions if 'TIMEOUT' in e.get('type', '')]
                
                self.findings.append(Finding(
                    control_id="IA-11",
                    control_title="Re-authentication",
                    check_name="Session Controls",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description=f"Session controls are active. {len(timeout_events)} timeout events in last 7 days.",
                    evidence={
                        'total_session_events': len(recent_sessions),
                        'timeout_events': len(timeout_events)
                    },
                    remediation="Continue monitoring session timeout settings",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.warning(f"Could not check session controls: {e}")
            
    def check_failed_login_attempts(self):
        """IA-2(8): Check for network access replay attacks"""
        logger.info("Checking failed login patterns...")
        
        try:
            # Get failed login events
            failed_logins = self.api.get_events(
                event_types=['FAILED_LOGIN'],
                created_after=(datetime.now() - timedelta(days=1)).isoformat()
            )
            
            if failed_logins:
                # Group by user/IP to detect attack patterns
                failure_by_user = {}
                failure_by_ip = {}
                
                for event in failed_logins:
                    user = event.get('created_by', 'unknown')
                    ip = event.get('ip_address', 'unknown')
                    
                    failure_by_user[user] = failure_by_user.get(user, 0) + 1
                    failure_by_ip[ip] = failure_by_ip.get(ip, 0) + 1
                
                # Check for brute force indicators
                suspicious_users = {u: c for u, c in failure_by_user.items() if c > 5}
                suspicious_ips = {ip: c for ip, c in failure_by_ip.items() if c > 10}
                
                if suspicious_users or suspicious_ips:
                    self.findings.append(Finding(
                        control_id="IA-2(8)",
                        control_title="Network Access - Replay Resistant",
                        check_name="Failed Login Analysis",
                        status=ComplianceStatus.NON_COMPLIANT,
                        severity=Severity.HIGH,
                        description=f"Potential brute force activity detected",
                        evidence={
                            'total_failures': len(failed_logins),
                            'suspicious_users': suspicious_users,
                            'suspicious_ips': list(suspicious_ips.keys())[:5]
                        },
                        remediation="Implement account lockout after 5 failed attempts and IP-based rate limiting",
                        cia_impact=CIAImpact("high", "high", "medium")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="IA-2(8)",
                        control_title="Network Access - Replay Resistant",
                        check_name="Failed Login Analysis",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description=f"Failed login attempts within normal range: {len(failed_logins)} in 24 hours",
                        evidence={'failed_login_count': len(failed_logins)},
                        remediation="Continue monitoring failed login attempts",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
            else:
                self.findings.append(Finding(
                    control_id="IA-2(8)",
                    control_title="Network Access - Replay Resistant",
                    check_name="Failed Login Analysis",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description="No failed login attempts in the last 24 hours",
                    evidence={'failed_login_count': 0},
                    remediation="Continue monitoring authentication attempts",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.error(f"Could not check failed logins: {e}")
            
    def check_sso_configuration(self):
        """IA-8: Check external authentication (SSO) configuration"""
        logger.info("Checking SSO configuration...")
        
        # Check for SSO-related events
        sso_events = ['SSO_LOGIN', 'SAML_LOGIN', 'OAUTH2_LOGIN']
        
        try:
            recent_sso = self.api.get_events(
                event_types=sso_events,
                created_after=(datetime.now() - timedelta(days=7)).isoformat()
            )
            
            # Also check sync-enabled users as indicator of SSO
            users = self.api.get_all_users(fields=['id', 'is_sync_enabled'])
            sso_users = [u for u in users if u.is_sync_enabled]
            sso_ratio = len(sso_users) / len(users) if users else 0
            
            if sso_ratio < 0.5 and not recent_sso:
                self.findings.append(Finding(
                    control_id="IA-8",
                    control_title="Identification and Authentication (Non-Organizational Users)",
                    check_name="SSO Configuration",
                    status=ComplianceStatus.NON_COMPLIANT,
                    severity=Severity.HIGH,
                    description=f"Low SSO adoption: only {sso_ratio:.1%} of users use SSO",
                    evidence={
                        'sso_users': len(sso_users),
                        'total_users': len(users),
                        'sso_ratio': sso_ratio
                    },
                    remediation="Implement enterprise SSO/SAML for centralized authentication management",
                    cia_impact=CIAImpact("high", "high", "medium")
                ))
            else:
                self.findings.append(Finding(
                    control_id="IA-8",
                    control_title="Identification and Authentication (Non-Organizational Users)",
                    check_name="SSO Configuration",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description=f"SSO is configured for {sso_ratio:.1%} of users",
                    evidence={
                        'sso_ratio': sso_ratio,
                        'recent_sso_logins': len(recent_sso) if recent_sso else 0
                    },
                    remediation="Continue expanding SSO adoption",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.warning(f"Could not check SSO configuration: {e}")
            
    def check_service_accounts(self):
        """IA-4: Check identifier management for service accounts"""
        logger.info("Checking service account management...")
        
        users = self.api.get_all_users(fields=['id', 'name', 'login', 'created_at', 'modified_at'])
        
        # Identify potential service accounts
        service_patterns = ['service', 'app', 'api', 'system', 'automation', 'integration', 'bot']
        service_accounts = []
        
        for user in users:
            if any(pattern in user.login.lower() for pattern in service_patterns):
                # Check if account has been active
                try:
                    modified_date = datetime.fromisoformat(user.modified_at.replace('Z', '+00:00'))
                    days_since_modified = (datetime.now() - modified_date.replace(tzinfo=None)).days
                    
                    service_accounts.append({
                        'login': user.login,
                        'name': user.name,
                        'days_since_activity': days_since_modified
                    })
                except Exception as e:
                    logger.warning(f"Could not parse date for {user.login}: {e}")
        
        if service_accounts:
            # Check for inactive service accounts
            inactive_service = [sa for sa in service_accounts if sa['days_since_activity'] > 90]
            
            if inactive_service:
                self.findings.append(Finding(
                    control_id="IA-4",
                    control_title="Identifier Management",
                    check_name="Service Account Management",
                    status=ComplianceStatus.NON_COMPLIANT,
                    severity=Severity.MEDIUM,
                    description=f"Found {len(inactive_service)} inactive service accounts",
                    evidence={
                        'total_service_accounts': len(service_accounts),
                        'inactive_accounts': inactive_service[:5]
                    },
                    remediation="Review and disable unused service accounts. Implement regular service account audits.",
                    cia_impact=CIAImpact("high", "high", "low")
                ))
            else:
                self.findings.append(Finding(
                    control_id="IA-4",
                    control_title="Identifier Management",
                    check_name="Service Account Management",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description=f"Service accounts appear to be actively managed",
                    evidence={'service_account_count': len(service_accounts)},
                    remediation="Continue regular service account reviews",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
    def check_privileged_access(self):
        """IA-2(2): Check non-privileged access to non-privileged accounts"""
        logger.info("Checking privileged access patterns...")
        
        # Look for elevation of privilege events
        privilege_events = ['CHANGE_ADMIN_ROLE', 'GRANT_ADMIN_ACCESS', 'ADMIN_LOGIN']
        
        try:
            recent_privilege = self.api.get_events(
                event_types=privilege_events,
                created_after=(datetime.now() - timedelta(days=30)).isoformat()
            )
            
            if recent_privilege:
                # Analyze privilege changes
                role_changes = [e for e in recent_privilege if 'CHANGE_ADMIN_ROLE' in e.get('type', '')]
                
                if len(role_changes) > 10:
                    self.findings.append(Finding(
                        control_id="IA-2(2)",
                        control_title="Non-Privileged Access",
                        check_name="Privilege Escalation Activity",
                        status=ComplianceStatus.PARTIAL,
                        severity=Severity.MEDIUM,
                        description=f"High frequency of admin role changes: {len(role_changes)} in 30 days",
                        evidence={
                            'role_changes': len(role_changes),
                            'total_privilege_events': len(recent_privilege)
                        },
                        remediation="Review admin role assignment process and implement approval workflow",
                        cia_impact=CIAImpact("high", "high", "medium")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="IA-2(2)",
                        control_title="Non-Privileged Access",
                        check_name="Privilege Management",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description="Privilege changes are within normal range",
                        evidence={'privilege_events': len(recent_privilege)},
                        remediation="Continue monitoring privilege assignments",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
                    
        except Exception as e:
            logger.error(f"Could not check privileged access: {e}")