"""Access Control (AC) family compliance checks"""

import logging
from typing import List, Dict
from datetime import datetime, timedelta

from ..core.api_client import BoxAPIClient
from ..core.models import Finding, Severity, ComplianceStatus, CIAImpact

logger = logging.getLogger(__name__)


class AccessControlChecker:
    """Checks for NIST 800-53 Access Control family"""
    
    def __init__(self, api_client: BoxAPIClient):
        self.api = api_client
        self.findings = []
        
    def run_all_checks(self) -> List[Finding]:
        """Run all access control checks"""
        self.findings = []
        
        checks = [
            self.check_least_privilege,
            self.check_admin_roles,
            self.check_external_collaboration,
            self.check_inactive_users,
            self.check_shared_links,
            self.check_collaboration_whitelist,
            self.check_user_provisioning
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {e}")
                self.findings.append(Finding(
                    control_id="AC-ERR",
                    control_title="Access Control Check Error",
                    check_name=check.__name__,
                    status=ComplianceStatus.ERROR,
                    severity=Severity.MEDIUM,
                    description=f"Failed to execute check: {str(e)}",
                    evidence={"error": str(e)},
                    remediation="Investigate and resolve the error",
                    cia_impact=CIAImpact("medium", "medium", "low")
                ))
                
        return self.findings
        
    def check_least_privilege(self):
        """AC-2: Check for least privilege enforcement"""
        logger.info("Checking least privilege...")
        
        users = self.api.get_all_users(fields=['id', 'name', 'login', 'role', 'status'])
        
        # Count users by role
        role_counts = {}
        admin_users = []
        
        for user in users:
            role = user.role
            role_counts[role] = role_counts.get(role, 0) + 1
            
            if role in ['admin', 'coadmin']:
                admin_users.append({
                    'name': user.name,
                    'login': user.login,
                    'role': role
                })
        
        # Check admin ratio
        total_users = len(users)
        admin_count = role_counts.get('admin', 0) + role_counts.get('coadmin', 0)
        admin_ratio = admin_count / total_users if total_users > 0 else 0
        
        if admin_ratio > 0.1:  # More than 10% admins
            self.findings.append(Finding(
                control_id="AC-2",
                control_title="Account Management",
                check_name="Excessive Admin Privileges",
                status=ComplianceStatus.NON_COMPLIANT,
                severity=Severity.HIGH,
                description=f"High ratio of admin users detected: {admin_count}/{total_users} ({admin_ratio:.1%})",
                evidence={
                    'admin_count': admin_count,
                    'total_users': total_users,
                    'admin_ratio': admin_ratio,
                    'admin_users': admin_users[:10]  # First 10 for evidence
                },
                remediation="Review admin users and revoke unnecessary privileges. Aim for <10% admin ratio.",
                cia_impact=CIAImpact("high", "high", "medium")
            ))
        else:
            self.findings.append(Finding(
                control_id="AC-2",
                control_title="Account Management",
                check_name="Admin Privilege Ratio",
                status=ComplianceStatus.COMPLIANT,
                severity=Severity.INFO,
                description=f"Admin user ratio is acceptable: {admin_count}/{total_users} ({admin_ratio:.1%})",
                evidence={'role_distribution': role_counts},
                remediation="Continue monitoring admin user assignments",
                cia_impact=CIAImpact("low", "low", "low")
            ))
            
    def check_admin_roles(self):
        """AC-2(7): Check privileged user accounts"""
        logger.info("Checking admin role assignments...")
        
        users = self.api.get_all_users(fields=['id', 'name', 'login', 'role', 'created_at', 'modified_at'])
        
        admin_users = [u for u in users if u.role in ['admin', 'coadmin']]
        
        # Check for service accounts with admin privileges
        suspicious_admins = []
        for admin in admin_users:
            # Common service account patterns
            if any(pattern in admin.login.lower() for pattern in ['service', 'app', 'api', 'system', 'automation']):
                suspicious_admins.append({
                    'login': admin.login,
                    'name': admin.name,
                    'role': admin.role
                })
        
        if suspicious_admins:
            self.findings.append(Finding(
                control_id="AC-2(7)",
                control_title="Privileged User Accounts",
                check_name="Service Accounts with Admin Rights",
                status=ComplianceStatus.NON_COMPLIANT,
                severity=Severity.HIGH,
                description=f"Found {len(suspicious_admins)} potential service accounts with admin privileges",
                evidence={'suspicious_accounts': suspicious_admins},
                remediation="Review service accounts and use least privilege principle. Create dedicated service accounts with minimal required permissions.",
                cia_impact=CIAImpact("high", "high", "medium")
            ))
            
    def check_external_collaboration(self):
        """AC-3: Check external collaboration restrictions"""
        logger.info("Checking external collaboration settings...")
        
        users = self.api.get_all_users(fields=['id', 'login', 'is_external_collab_restricted'])
        
        unrestricted_users = [u for u in users if not u.is_external_collab_restricted]
        unrestricted_ratio = len(unrestricted_users) / len(users) if users else 0
        
        if unrestricted_ratio > 0.5:  # More than 50% can collaborate externally
            self.findings.append(Finding(
                control_id="AC-3",
                control_title="Access Enforcement",
                check_name="External Collaboration Restrictions",
                status=ComplianceStatus.NON_COMPLIANT,
                severity=Severity.HIGH,
                description=f"{len(unrestricted_users)} users ({unrestricted_ratio:.1%}) can collaborate externally without restrictions",
                evidence={
                    'unrestricted_count': len(unrestricted_users),
                    'total_users': len(users),
                    'sample_users': [u.login for u in unrestricted_users[:10]]
                },
                remediation="Enable external collaboration restrictions for users who don't require external sharing",
                cia_impact=CIAImpact("high", "medium", "low")
            ))
        else:
            self.findings.append(Finding(
                control_id="AC-3",
                control_title="Access Enforcement",
                check_name="External Collaboration Restrictions",
                status=ComplianceStatus.COMPLIANT,
                severity=Severity.INFO,
                description=f"External collaboration is appropriately restricted. {len(unrestricted_users)} users can collaborate externally",
                evidence={'unrestricted_ratio': unrestricted_ratio},
                remediation="Continue monitoring external collaboration settings",
                cia_impact=CIAImpact("low", "low", "low")
            ))
            
    def check_inactive_users(self):
        """AC-2(3): Check for inactive user accounts"""
        logger.info("Checking for inactive users...")
        
        users = self.api.get_all_users(fields=['id', 'name', 'login', 'status', 'created_at', 'modified_at'])
        
        # Check for users not modified in 90 days
        ninety_days_ago = datetime.now() - timedelta(days=90)
        inactive_users = []
        
        for user in users:
            if user.status == 'active':
                # Parse modified_at date
                try:
                    modified_date = datetime.fromisoformat(user.modified_at.replace('Z', '+00:00'))
                    if modified_date.replace(tzinfo=None) < ninety_days_ago:
                        inactive_users.append({
                            'login': user.login,
                            'name': user.name,
                            'last_modified': user.modified_at,
                            'days_inactive': (datetime.now() - modified_date.replace(tzinfo=None)).days
                        })
                except Exception as e:
                    logger.warning(f"Could not parse date for user {user.login}: {e}")
        
        if inactive_users:
            self.findings.append(Finding(
                control_id="AC-2(3)",
                control_title="Disable Inactive Accounts",
                check_name="Inactive User Accounts",
                status=ComplianceStatus.NON_COMPLIANT,
                severity=Severity.MEDIUM,
                description=f"Found {len(inactive_users)} active accounts not modified in 90+ days",
                evidence={
                    'inactive_count': len(inactive_users),
                    'sample_users': inactive_users[:10]
                },
                remediation="Review and disable inactive accounts. Implement automated account disabling after 90 days of inactivity.",
                cia_impact=CIAImpact("medium", "medium", "low")
            ))
        else:
            self.findings.append(Finding(
                control_id="AC-2(3)",
                control_title="Disable Inactive Accounts",
                check_name="Inactive User Accounts",
                status=ComplianceStatus.COMPLIANT,
                severity=Severity.INFO,
                description="No inactive user accounts found",
                evidence={'inactive_count': 0},
                remediation="Continue monitoring for inactive accounts",
                cia_impact=CIAImpact("low", "low", "low")
            ))
            
    def check_shared_links(self):
        """AC-3(9): Check for uncontrolled shared links"""
        logger.info("Checking shared link policies...")
        
        # This would require iterating through files/folders to check shared links
        # For now, we'll check if we can get enterprise settings about shared links
        
        try:
            settings = self.api.get_enterprise_settings()
            
            # Check for shared link settings in enterprise
            self.findings.append(Finding(
                control_id="AC-3(9)",
                control_title="Controlled Release",
                check_name="Shared Link Controls",
                status=ComplianceStatus.PARTIAL,
                severity=Severity.MEDIUM,
                description="Unable to fully assess shared link controls. Manual review required.",
                evidence={'enterprise_settings': settings},
                remediation="Review shared link settings: require passwords, set expiration dates, restrict download permissions",
                cia_impact=CIAImpact("high", "medium", "low")
            ))
        except Exception as e:
            logger.error(f"Could not check shared links: {e}")
            
    def check_collaboration_whitelist(self):
        """AC-4: Check information flow enforcement via collaboration whitelist"""
        logger.info("Checking collaboration whitelist...")
        
        whitelist = self.api.get_collaboration_whitelist()
        
        if not whitelist:
            self.findings.append(Finding(
                control_id="AC-4",
                control_title="Information Flow Enforcement",
                check_name="Collaboration Whitelist",
                status=ComplianceStatus.NON_COMPLIANT,
                severity=Severity.HIGH,
                description="No collaboration whitelist configured. External collaboration is unrestricted.",
                evidence={'whitelist_entries': 0},
                remediation="Configure collaboration whitelist to restrict external sharing to approved domains only",
                cia_impact=CIAImpact("high", "medium", "low")
            ))
        else:
            # Check for overly permissive entries
            permissive_entries = [e for e in whitelist if e.get('direction') == 'both']
            
            if len(permissive_entries) > 5:
                self.findings.append(Finding(
                    control_id="AC-4",
                    control_title="Information Flow Enforcement",
                    check_name="Collaboration Whitelist",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.MEDIUM,
                    description=f"Collaboration whitelist has {len(permissive_entries)} bidirectional entries",
                    evidence={
                        'total_entries': len(whitelist),
                        'bidirectional_entries': len(permissive_entries),
                        'domains': [e['domain'] for e in whitelist]
                    },
                    remediation="Review whitelist entries and restrict to minimum necessary domains",
                    cia_impact=CIAImpact("medium", "medium", "low")
                ))
            else:
                self.findings.append(Finding(
                    control_id="AC-4",
                    control_title="Information Flow Enforcement",
                    check_name="Collaboration Whitelist",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description=f"Collaboration whitelist is configured with {len(whitelist)} entries",
                    evidence={'whitelist_count': len(whitelist)},
                    remediation="Continue monitoring and updating whitelist as needed",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
    def check_user_provisioning(self):
        """AC-2(1): Check automated account management"""
        logger.info("Checking user provisioning...")
        
        users = self.api.get_all_users(fields=['id', 'login', 'is_sync_enabled'])
        
        sync_enabled_users = [u for u in users if u.is_sync_enabled]
        sync_ratio = len(sync_enabled_users) / len(users) if users else 0
        
        if sync_ratio < 0.8:  # Less than 80% using automated provisioning
            self.findings.append(Finding(
                control_id="AC-2(1)",
                control_title="Automated System Account Management",
                check_name="User Provisioning Automation",
                status=ComplianceStatus.PARTIAL,
                severity=Severity.MEDIUM,
                description=f"Only {len(sync_enabled_users)} users ({sync_ratio:.1%}) are managed through automated provisioning",
                evidence={
                    'sync_enabled_count': len(sync_enabled_users),
                    'manual_count': len(users) - len(sync_enabled_users),
                    'sync_ratio': sync_ratio
                },
                remediation="Implement SSO/SCIM for automated user provisioning and deprovisioning",
                cia_impact=CIAImpact("medium", "high", "low")
            ))
        else:
            self.findings.append(Finding(
                control_id="AC-2(1)",
                control_title="Automated System Account Management",
                check_name="User Provisioning Automation",
                status=ComplianceStatus.COMPLIANT,
                severity=Severity.INFO,
                description=f"Automated provisioning is enabled for {sync_ratio:.1%} of users",
                evidence={'sync_ratio': sync_ratio},
                remediation="Continue using automated provisioning",
                cia_impact=CIAImpact("low", "low", "low")
            ))