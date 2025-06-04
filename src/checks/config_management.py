"""Configuration Management (CM) family compliance checks"""

import logging
from typing import List, Dict
from datetime import datetime, timedelta

from ..core.api_client import BoxAPIClient
from ..core.models import Finding, Severity, ComplianceStatus, CIAImpact

logger = logging.getLogger(__name__)


class ConfigurationManagementChecker:
    """Checks for NIST 800-53 Configuration Management family"""
    
    def __init__(self, api_client: BoxAPIClient):
        self.api = api_client
        self.findings = []
        
    def run_all_checks(self) -> List[Finding]:
        """Run all configuration management checks"""
        self.findings = []
        
        checks = [
            self.check_baseline_configuration,
            self.check_configuration_changes,
            self.check_least_functionality,
            self.check_component_inventory,
            self.check_unauthorized_changes,
            self.check_integration_security,
            self.check_default_settings
        ]
        
        for check in checks:
            try:
                check()
            except Exception as e:
                logger.error(f"Error in {check.__name__}: {e}")
                self.findings.append(Finding(
                    control_id="CM-ERR",
                    control_title="Configuration Management Check Error",
                    check_name=check.__name__,
                    status=ComplianceStatus.ERROR,
                    severity=Severity.MEDIUM,
                    description=f"Failed to execute check: {str(e)}",
                    evidence={"error": str(e)},
                    remediation="Investigate and resolve the error",
                    cia_impact=CIAImpact("medium", "high", "medium")
                ))
                
        return self.findings
        
    def check_baseline_configuration(self):
        """CM-2: Check baseline configuration documentation"""
        logger.info("Checking baseline configuration...")
        
        try:
            # Get current enterprise settings as baseline
            settings = self.api.get_enterprise_settings()
            
            # Check key security settings
            security_baseline = {
                'enterprise_configured': bool(settings.get('enterprise_id')),
                'created_date': settings.get('created_at'),
                'last_modified': settings.get('modified_at')
            }
            
            # Calculate age of configuration
            if settings.get('created_at'):
                try:
                    created_date = datetime.fromisoformat(settings['created_at'].replace('Z', '+00:00'))
                    config_age_days = (datetime.now() - created_date.replace(tzinfo=None)).days
                    security_baseline['config_age_days'] = config_age_days
                    
                    if config_age_days > 365:
                        self.findings.append(Finding(
                            control_id="CM-2",
                            control_title="Baseline Configuration",
                            check_name="Configuration Age",
                            status=ComplianceStatus.PARTIAL,
                            severity=Severity.MEDIUM,
                            description=f"Enterprise configuration is {config_age_days} days old. Annual review recommended.",
                            evidence=security_baseline,
                            remediation="Document current configuration as baseline and establish regular review schedule",
                            cia_impact=CIAImpact("medium", "high", "medium")
                        ))
                    else:
                        self.findings.append(Finding(
                            control_id="CM-2",
                            control_title="Baseline Configuration",
                            check_name="Configuration Documentation",
                            status=ComplianceStatus.COMPLIANT,
                            severity=Severity.INFO,
                            description="Enterprise configuration appears to be maintained",
                            evidence=security_baseline,
                            remediation="Continue regular configuration reviews and documentation",
                            cia_impact=CIAImpact("low", "low", "low")
                        ))
                except Exception as e:
                    logger.warning(f"Could not parse configuration date: {e}")
                    
        except Exception as e:
            logger.error(f"Could not check baseline configuration: {e}")
            
    def check_configuration_changes(self):
        """CM-3: Check configuration change control"""
        logger.info("Checking configuration changes...")
        
        # Look for configuration change events
        config_events = ['ENTERPRISE_SETTINGS_UPDATE', 'ADMIN_SETTINGS_UPDATE', 
                        'SECURITY_SETTINGS_UPDATE', 'TERMS_OF_SERVICE_UPDATE']
        
        try:
            recent_changes = self.api.get_events(
                event_types=config_events,
                created_after=(datetime.now() - timedelta(days=30)).isoformat()
            )
            
            if recent_changes:
                # Group changes by user
                changes_by_user = {}
                for event in recent_changes:
                    user = event.get('created_by', 'unknown')
                    changes_by_user[user] = changes_by_user.get(user, 0) + 1
                
                # Check if changes are from multiple admins (good) or single admin (risky)
                if len(changes_by_user) == 1 and len(recent_changes) > 5:
                    self.findings.append(Finding(
                        control_id="CM-3",
                        control_title="Configuration Change Control",
                        check_name="Change Authorization",
                        status=ComplianceStatus.PARTIAL,
                        severity=Severity.MEDIUM,
                        description=f"All {len(recent_changes)} configuration changes made by single admin",
                        evidence={
                            'total_changes': len(recent_changes),
                            'admins_making_changes': list(changes_by_user.keys())
                        },
                        remediation="Implement change approval process with multiple administrators",
                        cia_impact=CIAImpact("medium", "high", "medium")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="CM-3",
                        control_title="Configuration Change Control",
                        check_name="Configuration Changes",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description=f"Configuration changes appear controlled. {len(recent_changes)} changes by {len(changes_by_user)} admins.",
                        evidence={
                            'change_count': len(recent_changes),
                            'unique_admins': len(changes_by_user)
                        },
                        remediation="Continue monitoring configuration changes",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
            else:
                self.findings.append(Finding(
                    control_id="CM-3",
                    control_title="Configuration Change Control",
                    check_name="Configuration Stability",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description="No configuration changes in the last 30 days",
                    evidence={'recent_changes': 0},
                    remediation="Ensure configuration changes are tracked when made",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.error(f"Could not check configuration changes: {e}")
            
    def check_least_functionality(self):
        """CM-7: Check for unnecessary features/services"""
        logger.info("Checking least functionality...")
        
        # Look for potentially risky features
        risky_events = ['PUBLIC_SHARE', 'OPEN_SHARED_LINK', 'REMOVE_DEVICE_ASSOCIATION',
                       'GRANTED_EXEMPT_DEVICE_LIMITS', 'APP_CREATED']
        
        try:
            recent_risky = self.api.get_events(
                event_types=risky_events,
                created_after=(datetime.now() - timedelta(days=7)).isoformat()
            )
            
            # Count risky activities
            risk_summary = {}
            for event in recent_risky:
                event_type = event['type']
                risk_summary[event_type] = risk_summary.get(event_type, 0) + 1
            
            # High risk if many public shares or open links
            public_shares = risk_summary.get('PUBLIC_SHARE', 0) + risk_summary.get('OPEN_SHARED_LINK', 0)
            
            if public_shares > 20:
                self.findings.append(Finding(
                    control_id="CM-7",
                    control_title="Least Functionality",
                    check_name="Public Sharing",
                    status=ComplianceStatus.NON_COMPLIANT,
                    severity=Severity.HIGH,
                    description=f"Excessive public sharing detected: {public_shares} public shares/links in 7 days",
                    evidence={
                        'public_shares': public_shares,
                        'risk_summary': risk_summary
                    },
                    remediation="Restrict public sharing capabilities and review shared links",
                    cia_impact=CIAImpact("high", "medium", "low")
                ))
            elif recent_risky:
                self.findings.append(Finding(
                    control_id="CM-7",
                    control_title="Least Functionality",
                    check_name="Feature Usage",
                    status=ComplianceStatus.PARTIAL,
                    severity=Severity.MEDIUM,
                    description="Some potentially risky features in use",
                    evidence={'risk_events': len(recent_risky), 'summary': risk_summary},
                    remediation="Review feature usage and disable unnecessary capabilities",
                    cia_impact=CIAImpact("medium", "medium", "low")
                ))
            else:
                self.findings.append(Finding(
                    control_id="CM-7",
                    control_title="Least Functionality",
                    check_name="Feature Restrictions",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description="No excessive use of risky features detected",
                    evidence={'risky_events': 0},
                    remediation="Continue restricting unnecessary features",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.error(f"Could not check functionality: {e}")
            
    def check_component_inventory(self):
        """CM-8: Check system component inventory"""
        logger.info("Checking component inventory...")
        
        inventory_status = {}
        
        try:
            # Check user inventory
            users = self.api.get_all_users()
            inventory_status['total_users'] = len(users)
            inventory_status['active_users'] = len([u for u in users if u.status == 'active'])
            
            # Check groups
            groups = self.api.get_all_groups()
            inventory_status['total_groups'] = len(groups)
            
            # Check device pins (trusted devices)
            device_pins = self.api.get_device_pins()
            inventory_status['trusted_devices'] = len(device_pins)
            
            # Check legal holds (compliance tools)
            legal_holds = self.api.get_legal_holds()
            inventory_status['legal_holds'] = len(legal_holds)
            
            # Evaluate inventory completeness
            if inventory_status['total_users'] > 0:
                inactive_ratio = (inventory_status['total_users'] - inventory_status['active_users']) / inventory_status['total_users']
                
                if inactive_ratio > 0.2:  # More than 20% inactive
                    self.findings.append(Finding(
                        control_id="CM-8",
                        control_title="Information System Component Inventory",
                        check_name="User Inventory",
                        status=ComplianceStatus.PARTIAL,
                        severity=Severity.MEDIUM,
                        description=f"High number of inactive users: {inactive_ratio:.1%} of total users",
                        evidence=inventory_status,
                        remediation="Clean up inactive user accounts and maintain accurate inventory",
                        cia_impact=CIAImpact("medium", "medium", "low")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="CM-8",
                        control_title="Information System Component Inventory",
                        check_name="Component Inventory",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description="System component inventory appears well-maintained",
                        evidence=inventory_status,
                        remediation="Continue regular inventory reviews",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
                    
        except Exception as e:
            logger.error(f"Could not check inventory: {e}")
            
    def check_unauthorized_changes(self):
        """CM-5: Check for unauthorized changes"""
        logger.info("Checking for unauthorized changes...")
        
        # Look for suspicious change events
        suspicious_events = ['REMOVE_DEVICE_ASSOCIATION', 'REMOVE_LOGIN_ACTIVITY_DEVICE',
                           'DELETE_USER', 'CHANGE_ADMIN_ROLE', 'OAUTH2_ACCESS_TOKEN_REVOKED']
        
        try:
            recent_suspicious = self.api.get_events(
                event_types=suspicious_events,
                created_after=(datetime.now() - timedelta(days=7)).isoformat()
            )
            
            if recent_suspicious:
                # Check for patterns indicating unauthorized changes
                delete_events = [e for e in recent_suspicious if 'DELETE' in e['type'] or 'REMOVE' in e['type']]
                role_changes = [e for e in recent_suspicious if 'ADMIN_ROLE' in e['type']]
                
                if len(delete_events) > 10:
                    self.findings.append(Finding(
                        control_id="CM-5",
                        control_title="Access Restrictions for Change",
                        check_name="Suspicious Deletions",
                        status=ComplianceStatus.NON_COMPLIANT,
                        severity=Severity.HIGH,
                        description=f"High number of deletion events: {len(delete_events)} in 7 days",
                        evidence={
                            'deletion_events': len(delete_events),
                            'role_changes': len(role_changes),
                            'total_suspicious': len(recent_suspicious)
                        },
                        remediation="Review deletion events for unauthorized changes and restrict change permissions",
                        cia_impact=CIAImpact("high", "high", "medium")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="CM-5",
                        control_title="Access Restrictions for Change",
                        check_name="Change Authorization",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description="Change events appear normal and controlled",
                        evidence={'suspicious_events': len(recent_suspicious)},
                        remediation="Continue monitoring for unauthorized changes",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
            else:
                self.findings.append(Finding(
                    control_id="CM-5",
                    control_title="Access Restrictions for Change",
                    check_name="Change Activity",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description="No suspicious change activity detected",
                    evidence={'suspicious_events': 0},
                    remediation="Continue monitoring system changes",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.error(f"Could not check unauthorized changes: {e}")
            
    def check_integration_security(self):
        """CM-7(5): Check third-party integrations"""
        logger.info("Checking integration security...")
        
        # Look for app and integration events
        integration_events = ['APP_CREATED', 'APP_AUTH_AUTHORIZATION', 'OAUTH2_ACCESS_TOKEN_CREATED',
                            'ADD_DEVICE_ASSOCIATION', 'APPLICATION_CREATED']
        
        try:
            recent_integrations = self.api.get_events(
                event_types=integration_events,
                created_after=(datetime.now() - timedelta(days=30)).isoformat()
            )
            
            if recent_integrations:
                # Count unique apps/integrations
                app_creations = [e for e in recent_integrations if 'APP_CREATED' in e['type'] or 'APPLICATION_CREATED' in e['type']]
                oauth_tokens = [e for e in recent_integrations if 'OAUTH2' in e['type']]
                
                if len(app_creations) > 5:
                    self.findings.append(Finding(
                        control_id="CM-7(5)",
                        control_title="Authorized Software / Whitelisting",
                        check_name="Third-Party Integrations",
                        status=ComplianceStatus.PARTIAL,
                        severity=Severity.MEDIUM,
                        description=f"High number of new integrations: {len(app_creations)} apps created in 30 days",
                        evidence={
                            'new_apps': len(app_creations),
                            'oauth_tokens': len(oauth_tokens),
                            'total_integration_events': len(recent_integrations)
                        },
                        remediation="Review and approve all third-party integrations. Implement app whitelisting.",
                        cia_impact=CIAImpact("high", "medium", "low")
                    ))
                else:
                    self.findings.append(Finding(
                        control_id="CM-7(5)",
                        control_title="Authorized Software / Whitelisting",
                        check_name="Integration Management",
                        status=ComplianceStatus.COMPLIANT,
                        severity=Severity.INFO,
                        description="Third-party integrations appear controlled",
                        evidence={
                            'integration_events': len(recent_integrations),
                            'new_apps': len(app_creations)
                        },
                        remediation="Continue reviewing and approving integrations",
                        cia_impact=CIAImpact("low", "low", "low")
                    ))
            else:
                self.findings.append(Finding(
                    control_id="CM-7(5)",
                    control_title="Authorized Software / Whitelisting",
                    check_name="Integration Activity",
                    status=ComplianceStatus.COMPLIANT,
                    severity=Severity.INFO,
                    description="No new integrations detected in the last 30 days",
                    evidence={'integration_events': 0},
                    remediation="Maintain integration approval process",
                    cia_impact=CIAImpact("low", "low", "low")
                ))
                
        except Exception as e:
            logger.error(f"Could not check integrations: {e}")
            
    def check_default_settings(self):
        """CM-6: Check security configuration settings"""
        logger.info("Checking default security settings...")
        
        # This is a meta-check that summarizes security posture
        security_indicators = {
            'checks_performed': True,
            'enterprise_configured': True
        }
        
        try:
            # Check if we have any public share events (bad default)
            public_events = self.api.get_events(
                event_types=['PUBLIC_SHARE', 'OPEN_SHARED_LINK'],
                created_after=(datetime.now() - timedelta(days=1)).isoformat()
            )
            
            security_indicators['public_sharing_active'] = len(public_events) > 0
            
            # Check collaboration whitelist (good if exists)
            whitelist = self.api.get_collaboration_whitelist()
            security_indicators['collaboration_restricted'] = len(whitelist) > 0
            
            # Calculate security score
            if security_indicators['public_sharing_active']:
                status = ComplianceStatus.PARTIAL
                severity = Severity.MEDIUM
                description = "Some insecure default settings detected (public sharing enabled)"
            elif security_indicators['collaboration_restricted']:
                status = ComplianceStatus.COMPLIANT
                severity = Severity.INFO
                description = "Security settings appear properly configured"
            else:
                status = ComplianceStatus.PARTIAL
                severity = Severity.MEDIUM
                description = "Security settings could be strengthened"
            
            self.findings.append(Finding(
                control_id="CM-6",
                control_title="Configuration Settings",
                check_name="Security Configuration",
                status=status,
                severity=severity,
                description=description,
                evidence=security_indicators,
                remediation="Review and harden all security settings according to baseline configuration",
                cia_impact=CIAImpact("medium", "high", "low")
            ))
            
        except Exception as e:
            logger.error(f"Could not check default settings: {e}")