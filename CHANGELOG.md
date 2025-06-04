# Changelog

All notable changes to the Box Audit project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2024-01-XX

### Added
- Initial release of Box Audit tool
- Support for NIST 800-53 control families:
  - Access Control (AC)
  - Audit and Accountability (AU)
  - Identification and Authentication (IA)
  - System and Communications Protection (SC)
  - Configuration Management (CM)
- Multiple output formats: text, JSON, HTML
- CIA impact assessment for all findings
- Comprehensive API limitations documentation
- FedRAMP moderate baseline focus
- Box JWT authentication support
- Command-line interface with various options
- Detailed remediation guidance for all findings

### Security
- Secure handling of Box JWT configuration files
- No storage of sensitive data in reports
- Proper error handling for API failures

### Documentation
- Comprehensive README with setup instructions
- Box API setup guide
- API limitations documentation
- Contributing guidelines
- Apache 2.0 license

[1.0.0]: https://github.com/hackidle/box-audit/releases/tag/v1.0.0