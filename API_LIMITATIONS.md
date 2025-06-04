# Box API Limitations for Compliance Checking

This document outlines security controls and configurations that cannot be fully verified through the Box API and require manual review in the Box Admin Console or additional documentation.

## Authentication & Identity Management

### Cannot Verify via API:
1. **Password Complexity Requirements**
   - Minimum length, character requirements, dictionary checks
   - Password history enforcement
   - Manual Review: Admin Console → Business Settings → Security

2. **Session Timeout Settings**
   - Idle timeout duration
   - Maximum session length
   - Manual Review: Admin Console → Business Settings → Security

3. **SSO/SAML Configuration Details**
   - Identity provider settings
   - Attribute mappings
   - SSO enforcement for specific groups
   - Manual Review: Admin Console → Enterprise Settings → SSO

4. **MFA Enforcement Settings**
   - Whether MFA is mandatory vs optional
   - MFA exemption groups
   - Backup authentication methods
   - Manual Review: Admin Console → Business Settings → Security

## Access Control & Permissions

### Cannot Verify via API:
1. **Default Folder Permissions**
   - New folder default sharing settings
   - Inherited permission models
   - Manual Review: Admin Console → Content & Sharing → Sharing Settings

2. **External Collaboration Details**
   - Specific domain restrictions beyond whitelist
   - Granular external user permissions
   - Manual Review: Admin Console → Business Settings → External Collaboration

3. **Download/Upload Restrictions**
   - File type restrictions
   - Size limits
   - Manual Review: Admin Console → Content & Sharing → Content Settings

## Data Protection & Encryption

### Cannot Verify via API:
1. **Box KeySafe Configuration**
   - Customer-managed encryption keys
   - Key rotation schedules
   - HSM integration
   - Manual Review: Requires separate Box KeySafe console

2. **Box Shield Rules**
   - Specific DLP policies and rules
   - Smart access patterns
   - Threat detection thresholds
   - Manual Review: Box Shield Admin Console (if licensed)

3. **Watermarking Policies**
   - Which folders/classifications require watermarking
   - Watermark templates and text
   - Manual Review: Admin Console → Business Settings → Watermarking

## Audit & Compliance

### Cannot Verify via API:
1. **Retention Policy Details**
   - Specific retention rules and durations
   - Disposition actions
   - Policy assignments
   - Manual Review: Admin Console → Governance → Retention Policies

2. **Legal Hold Configurations**
   - Hold criteria and filters
   - Custodian assignments
   - Manual Review: Admin Console → Governance → Legal Holds

3. **Alert Configurations**
   - Admin alert recipients
   - Alert thresholds and triggers
   - Notification methods
   - Manual Review: Admin Console → Reports → Alerts

## Network & Infrastructure

### Cannot Verify via API:
1. **IP Allowlisting**
   - Allowed IP ranges
   - Bypass groups
   - Manual Review: Admin Console → Business Settings → Security

2. **Network Zone Configuration**
   - Trusted network definitions
   - Zone-based access policies
   - Manual Review: Admin Console → Business Settings → Network Zones

3. **Email Domain Restrictions**
   - Allowed email domains for user accounts
   - Auto-provisioning rules
   - Manual Review: Admin Console → User Settings

## Compliance Features

### Cannot Verify via API:
1. **HIPAA/FedRAMP Settings**
   - Compliance mode enablement
   - Specific compliance configurations
   - Manual Review: Admin Console → Business Settings → Compliance

2. **Content Security Policies**
   - Malware scanning settings
   - Virus scan on upload
   - Threat intelligence integration
   - Manual Review: Admin Console → Content & Sharing → Security

3. **Terms of Service**
   - Custom terms acceptance
   - User acknowledgment tracking
   - Manual Review: Admin Console → Business Settings → Custom Setup

## Integration Security

### Cannot Verify via API:
1. **OAuth App Restrictions**
   - Approved app whitelist
   - App permission scopes
   - User consent settings
   - Manual Review: Admin Console → Apps → App Management

2. **API Rate Limits**
   - Custom rate limit configurations
   - Per-app throttling
   - Manual Review: Admin Console → Apps → Custom Applications

## Recommendations for Complete Compliance Verification

### 1. Create a Manual Checklist
Maintain a checklist of settings that must be verified manually in the Box Admin Console alongside the automated audit.

### 2. Document Current Settings
Take screenshots or export configurations from the Admin Console for:
- Security settings
- Authentication policies  
- Sharing restrictions
- Compliance configurations

### 3. Regular Manual Reviews
Schedule quarterly manual reviews of:
- Admin Console security settings
- User access reports
- Integration permissions
- Alert configurations

### 4. Maintain Configuration Baselines
Document your organization's Box configuration baseline including:
- Security settings
- Authentication requirements
- Sharing policies
- Retention rules

### 5. Use Box's Built-in Reports
Leverage Box's native reporting for:
- User activity reports
- Admin activity logs
- Security dashboards
- Compliance reports

## Working with Box Support

For FedRAMP compliance, consider:
1. Requesting Box's FedRAMP attestation documentation
2. Engaging Box's compliance team for configuration reviews
3. Using Box Consulting services for security optimization
4. Participating in Box's security webinars and training

## Important Notes

- This tool provides automated checking for configurations accessible via API
- A complete FedRAMP audit requires both automated and manual verification
- Some features (like Box Shield) require additional licensing
- Box's API permissions may limit access to certain security configurations
- Always verify critical security settings directly in the Admin Console