# Box FedRAMP Compliance Audit Tool

A comprehensive security compliance audit tool for Box.com that validates configurations against FedRAMP moderate baseline and NIST 800-53 controls.

## Features

- **Automated Compliance Checking**: Validates Box configuration against NIST 800-53 control families
- **CIA Impact Assessment**: Evaluates findings based on Confidentiality, Integrity, and Availability impact
- **Multiple Output Formats**: Generate reports in text, JSON, or HTML format
- **FedRAMP Focused**: Designed specifically for FedRAMP moderate baseline requirements
- **Comprehensive Coverage**: Checks Access Control, Audit & Accountability, Identification & Authentication, and more

## Quick Start

### Prerequisites

1. Box Enterprise Admin access
2. Python 3.8 or higher
3. Box JWT application configured (see [BOX_API_SETUP.md](BOX_API_SETUP.md))

### Installation

```bash
# Clone the repository
git clone https://github.com/hackidle/box-audit.git
cd box-audit

# Install the package
pip install -e .

# Or install dependencies manually
pip install -r requirements.txt
```

### Configuration

1. Follow the instructions in [BOX_API_SETUP.md](BOX_API_SETUP.md) to create a Box JWT application
2. Download your JWT config file and save it as `box_config.json`
3. Ensure the file is protected:
   ```bash
   chmod 600 box_config.json
   echo "box_config.json" >> .gitignore
   ```

### Usage

#### Test Connection
```bash
python test_connection.py
```

#### Run Compliance Audit
```bash
# Using installed command (after pip install -e .)
box-audit

# Or using Python directly
python box_audit.py

# Generate HTML report
box-audit --output-format html --output report.html

# Generate JSON report for integration
box-audit --output-format json --output findings.json

# Use alternative config file
box-audit --config ~/secure/box_jwt.json
```

### Command Line Options

- `--config PATH`: Path to Box JWT config file (default: box_config.json)
- `--output-format {text,json,html}`: Output format for the report (default: text)
- `--output PATH`: Save report to file instead of stdout
- `--verbose`: Show detailed debug information

## Security Checks Performed

### Access Control (AC)
- Least privilege enforcement
- Admin role assignments
- External collaboration settings
- Inactive user detection
- Shared link controls
- Collaboration whitelist

### Audit & Accountability (AU)
- Audit logging configuration
- Admin activity monitoring
- Event retention policies
- Security event detection
- Audit log access controls
- Time stamp accuracy

### Identification & Authentication (IA)
- Multi-factor authentication enforcement
- Password policy strength
- Session controls
- Failed login monitoring
- SSO configuration
- Service account management

### System & Communications Protection (SC)
- Encryption at rest verification
- Encryption in transit (TLS) monitoring
- Data loss prevention controls
- Watermarking configuration
- Classification labels
- API security monitoring
- Network boundary protection
- Mobile device security

### Configuration Management (CM)
- Baseline configuration documentation
- Configuration change tracking
- Least functionality principle
- System component inventory
- Unauthorized change detection
- Third-party integration security
- Security settings validation

## Report Interpretation

### Severity Levels
- **CRITICAL**: Immediate action required, severe security risk
- **HIGH**: High priority fixes needed for compliance
- **MEDIUM**: Should be addressed in remediation plan
- **LOW**: Minor issues or recommendations
- **INFO**: Compliant items for awareness

### Compliance Status
- **COMPLIANT**: Meets FedRAMP requirements
- **NON_COMPLIANT**: Fails to meet requirements
- **PARTIAL**: Partially meets requirements
- **NOT_APPLICABLE**: Control not applicable to Box
- **ERROR**: Unable to check due to technical issues

### CIA Impact Ratings
Each finding includes impact assessment for:
- **Confidentiality**: Risk of unauthorized information disclosure
- **Integrity**: Risk of unauthorized information modification
- **Availability**: Risk of disruption to information access

## Exit Codes

- `0`: Success, no critical/high findings
- `1`: High severity findings detected
- `2`: Critical severity findings detected
- `3`: Configuration error
- `4`: Runtime error

## Architecture

See [COMPLIANCE_PLAN.md](COMPLIANCE_PLAN.md) for detailed architecture and implementation details.

## Important: API Limitations

Not all security controls can be verified through the Box API. See [API_LIMITATIONS.md](API_LIMITATIONS.md) for a comprehensive list of settings that require manual verification in the Box Admin Console.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

- **Never commit Box JWT config files** - these contain private keys
- Use environment variables for sensitive configuration
- Report security vulnerabilities privately to security@hackidle.com
- See [SECURITY.md](SECURITY.md) for our security policy

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- NIST for the 800-53 security control framework
- Box.com for their comprehensive API documentation
- The FedRAMP program for standardizing cloud security assessments
