# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in this project, please follow these steps:

### 1. Do NOT Create a Public Issue

Security vulnerabilities should not be reported through public GitHub issues.

### 2. Email Us Privately

Send details to: security@hackidle.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### 3. Wait for Response

We will acknowledge receipt within 48 hours and provide an expected timeline for a fix.

## Security Best Practices for Users

### Protecting Box JWT Credentials

1. **Never commit JWT config files**
   ```bash
   # Ensure these are in .gitignore
   box_config.json
   *_config.json
   *.pem
   *.key
   ```

2. **Use environment variables**
   ```bash
   export BOX_CONFIG_PATH=/secure/location/box_config.json
   ```

3. **Restrict file permissions**
   ```bash
   chmod 600 box_config.json
   ```

### Secure Report Handling

1. **Reports may contain sensitive data**
   - User lists
   - Permission structures
   - Configuration details

2. **Store reports securely**
   - Encrypt report files
   - Restrict access to authorized personnel
   - Delete reports after review

3. **Sanitize before sharing**
   - Remove user PII
   - Redact enterprise IDs
   - Anonymize email addresses

### API Token Security

1. **Rotate JWT keys regularly**
   - Generate new keypairs every 90 days
   - Remove old keys from Box app

2. **Monitor API access**
   - Review Box API logs
   - Check for unusual activity
   - Revoke suspicious tokens

### Running Audits Securely

1. **Use a dedicated service account**
   - Don't use personal admin accounts
   - Create audit-specific Box app
   - Limit permissions to read-only

2. **Run from secure environment**
   - Use a hardened system
   - Keep Python dependencies updated
   - Run in isolated environment

3. **Protect audit logs**
   - Secure tool output
   - Monitor who runs audits
   - Track audit frequency

## Vulnerability Disclosure Timeline

1. **0 days**: Vulnerability reported
2. **2 days**: Initial response and assessment
3. **7 days**: Fix development begins
4. **30 days**: Fix released (critical issues faster)
5. **90 days**: Public disclosure (coordinated)

## Security Features

This tool includes several security features:

- No storage of credentials in code
- Secure API communication via Box SDK
- Read-only operations (no modifications)
- Comprehensive error handling
- Input validation for all parameters

## Scope

The following are in scope for security reports:
- Authentication bypass
- Information disclosure
- Code injection
- Path traversal
- Credential exposure

The following are out of scope:
- Box platform vulnerabilities (report to Box)
- Denial of service attacks
- Social engineering
- Physical attacks

Thank you for helping keep this project secure!