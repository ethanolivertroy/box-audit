# Contributing to Box Audit

Thank you for your interest in contributing to the Box Audit project! This tool helps organizations validate their Box.com configurations against FedRAMP and NIST 800-53 security controls.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use issue templates when available
3. Include:
   - Clear description of the issue
   - Steps to reproduce
   - Expected vs actual behavior
   - Box API version (if relevant)
   - Python version and OS

### Suggesting Enhancements

1. Open an issue with the "enhancement" label
2. Describe the use case and benefits
3. Consider API limitations documented in API_LIMITATIONS.md

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes following our coding standards
4. Add or update tests as needed
5. Update documentation
6. Submit a pull request with a clear description

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/box-audit.git
cd box-audit

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available
```

## Coding Standards

### Python Style
- Follow PEP 8
- Use type hints where appropriate
- Maximum line length: 120 characters
- Use descriptive variable names

### Documentation
- Add docstrings to all functions and classes
- Update README.md for user-facing changes
- Document API limitations in API_LIMITATIONS.md

### Security Checks
When adding new security checks:

1. Place in appropriate module (access_control.py, audit_accountability.py, etc.)
2. Return Finding objects with:
   - Accurate NIST control mapping
   - Clear description and remediation
   - Appropriate severity level
   - CIA impact assessment
3. Handle API errors gracefully
4. Add logging for debugging

### Example Check Structure

```python
def check_example_control(self):
    """SC-XX: Check description"""
    logger.info("Checking example control...")
    
    try:
        # API calls
        data = self.api.get_some_data()
        
        # Analysis logic
        if not_compliant_condition:
            self.findings.append(Finding(
                control_id="SC-XX",
                control_title="Control Title",
                check_name="Specific Check Name",
                status=ComplianceStatus.NON_COMPLIANT,
                severity=Severity.HIGH,
                description="Clear description of the issue",
                evidence={'key': 'value'},
                remediation="Specific steps to fix",
                cia_impact=CIAImpact("high", "medium", "low")
            ))
    except Exception as e:
        logger.error(f"Could not check example: {e}")
```

## Testing

### Running Tests
```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=src

# Run specific test file
python -m pytest tests/test_access_control.py
```

### Writing Tests
- Test both positive and negative cases
- Mock Box API responses
- Test error handling
- Verify Finding objects are created correctly

## API Limitations

Before implementing new checks, review API_LIMITATIONS.md to understand what can and cannot be verified through the Box API. If your check requires manual verification, document it there.

## Commit Messages

Use clear, descriptive commit messages:
- `feat: Add check for shared link expiration`
- `fix: Handle missing user email in access control check`
- `docs: Update API limitations for retention policies`
- `test: Add unit tests for system protection module`

## Release Process

1. Update version in relevant files
2. Update CHANGELOG.md
3. Create pull request to main branch
4. After merge, tag the release

## Questions?

- Open an issue for questions
- Check existing documentation
- Review the Box API documentation at https://developer.box.com

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.