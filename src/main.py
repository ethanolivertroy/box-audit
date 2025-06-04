#!/usr/bin/env python3
"""Box FedRAMP Compliance Audit Tool"""

import argparse
import logging
import sys
import json
from datetime import datetime
from pathlib import Path

from .auth.box_authenticator import BoxAuthenticator
from .core.api_client import BoxAPIClient
from .core.models import ComplianceReport
from .checks import (
    AccessControlChecker,
    AuditAccountabilityChecker,
    IdentificationAuthChecker,
    SystemProtectionChecker,
    ConfigurationManagementChecker
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_compliance_audit(client: BoxAPIClient) -> ComplianceReport:
    """Run all compliance checks and generate report"""
    
    logger.info("Starting FedRAMP compliance audit...")
    
    # Get enterprise info
    enterprise_settings = client.get_enterprise_settings()
    
    # Initialize report
    report = ComplianceReport(
        enterprise_id=enterprise_settings['enterprise_id'],
        enterprise_name=enterprise_settings['enterprise_name'],
        scan_timestamp=datetime.now(),
        findings=[]
    )
    
    # Run all check modules
    checkers = [
        ("Access Control", AccessControlChecker(client)),
        ("Audit & Accountability", AuditAccountabilityChecker(client)),
        ("Identification & Authentication", IdentificationAuthChecker(client)),
        ("System & Communications Protection", SystemProtectionChecker(client)),
        ("Configuration Management", ConfigurationManagementChecker(client))
    ]
    
    for name, checker in checkers:
        logger.info(f"Running {name} checks...")
        try:
            findings = checker.run_all_checks()
            report.findings.extend(findings)
            logger.info(f"Completed {name} checks: {len(findings)} findings")
        except Exception as e:
            logger.error(f"Error in {name} checks: {e}")
    
    # Calculate summary
    report.calculate_summary()
    
    return report


def generate_text_report(report: ComplianceReport) -> str:
    """Generate human-readable text report"""
    
    lines = []
    lines.append("=" * 80)
    lines.append("BOX FEDRAMP COMPLIANCE AUDIT REPORT")
    lines.append("=" * 80)
    lines.append(f"Enterprise: {report.enterprise_name}")
    lines.append(f"Enterprise ID: {report.enterprise_id}")
    lines.append(f"Scan Date: {report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("⚠️  IMPORTANT: This report only includes checks available via Box API.")
    lines.append("   See API_LIMITATIONS.md for manual checks required in Box Admin Console.")
    lines.append("")
    
    # Summary
    lines.append("EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"Total Checks: {report.summary['total_checks']}")
    lines.append(f"Compliant: {report.summary['compliant']}")
    lines.append(f"Non-Compliant: {report.summary['non_compliant']}")
    lines.append(f"Partial: {report.summary['partial']}")
    lines.append(f"Compliance Score: {report.summary['compliance_score']}%")
    lines.append("")
    lines.append(f"Critical Findings: {report.summary['critical_findings']}")
    lines.append(f"High Findings: {report.summary['high_findings']}")
    lines.append("")
    
    # Group findings by severity
    critical_findings = [f for f in report.findings if f.severity.value == 'critical']
    high_findings = [f for f in report.findings if f.severity.value == 'high']
    medium_findings = [f for f in report.findings if f.severity.value == 'medium']
    
    # Critical findings detail
    if critical_findings:
        lines.append("CRITICAL FINDINGS")
        lines.append("=" * 80)
        for finding in critical_findings:
            lines.append(f"\n[{finding.control_id}] {finding.control_title}")
            lines.append(f"Check: {finding.check_name}")
            lines.append(f"Status: {finding.status.value.upper()}")
            lines.append(f"Description: {finding.description}")
            lines.append(f"CIA Impact: C:{finding.cia_impact.confidentiality} I:{finding.cia_impact.integrity} A:{finding.cia_impact.availability}")
            lines.append(f"Remediation: {finding.remediation}")
            lines.append("-" * 40)
    
    # High findings detail
    if high_findings:
        lines.append("\nHIGH SEVERITY FINDINGS")
        lines.append("=" * 80)
        for finding in high_findings:
            lines.append(f"\n[{finding.control_id}] {finding.control_title}")
            lines.append(f"Check: {finding.check_name}")
            lines.append(f"Status: {finding.status.value.upper()}")
            lines.append(f"Description: {finding.description}")
            lines.append(f"Remediation: {finding.remediation}")
            lines.append("-" * 40)
    
    # Summary of medium findings
    if medium_findings:
        lines.append(f"\nMEDIUM SEVERITY FINDINGS: {len(medium_findings)} issues found")
        lines.append("Run with --verbose to see all findings")
    
    return "\n".join(lines)


def generate_json_report(report: ComplianceReport) -> str:
    """Generate JSON format report"""
    
    report_dict = {
        'enterprise_id': report.enterprise_id,
        'enterprise_name': report.enterprise_name,
        'scan_timestamp': report.scan_timestamp.isoformat(),
        'summary': report.summary,
        'findings': [f.to_dict() for f in report.findings]
    }
    
    return json.dumps(report_dict, indent=2)


def generate_html_report(report: ComplianceReport) -> str:
    """Generate HTML format report"""
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Box FedRAMP Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .summary {{ margin: 20px 0; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .critical {{ border-color: #d9534f; background-color: #f9e9e9; }}
        .high {{ border-color: #f0ad4e; background-color: #fcf8e3; }}
        .medium {{ border-color: #5bc0de; background-color: #d9edf7; }}
        .compliant {{ border-color: #5cb85c; background-color: #dff0d8; }}
        .score {{ font-size: 48px; font-weight: bold; color: #333; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f0f0f0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Box FedRAMP Compliance Audit Report</h1>
        <p><strong>Enterprise:</strong> {report.enterprise_name}</p>
        <p><strong>Scan Date:</strong> {report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <div style="background-color: #fcf8e3; border: 1px solid #faebcc; padding: 10px; margin-top: 10px; border-radius: 5px;">
            <strong>⚠️ Important:</strong> This report only includes checks available via Box API. 
            See API_LIMITATIONS.md for settings requiring manual verification in Box Admin Console.
        </div>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="score">{report.summary['compliance_score']}%</div>
        <table>
            <tr>
                <th>Metric</th>
                <th>Count</th>
            </tr>
            <tr>
                <td>Total Checks</td>
                <td>{report.summary['total_checks']}</td>
            </tr>
            <tr>
                <td>Compliant</td>
                <td>{report.summary['compliant']}</td>
            </tr>
            <tr>
                <td>Non-Compliant</td>
                <td>{report.summary['non_compliant']}</td>
            </tr>
            <tr>
                <td>Critical Findings</td>
                <td>{report.summary['critical_findings']}</td>
            </tr>
            <tr>
                <td>High Findings</td>
                <td>{report.summary['high_findings']}</td>
            </tr>
        </table>
    </div>
    
    <h2>Findings</h2>
"""
    
    # Add findings
    for finding in sorted(report.findings, key=lambda f: f.severity.value):
        severity_class = finding.severity.value
        if finding.status.value == 'compliant':
            severity_class = 'compliant'
            
        html += f"""
    <div class="finding {severity_class}">
        <h3>[{finding.control_id}] {finding.control_title}</h3>
        <p><strong>Check:</strong> {finding.check_name}</p>
        <p><strong>Status:</strong> {finding.status.value.upper()}</p>
        <p><strong>Severity:</strong> {finding.severity.value.upper()}</p>
        <p><strong>Description:</strong> {finding.description}</p>
        <p><strong>CIA Impact:</strong> C:{finding.cia_impact.confidentiality} I:{finding.cia_impact.integrity} A:{finding.cia_impact.availability}</p>
        <p><strong>Remediation:</strong> {finding.remediation}</p>
    </div>
"""
    
    html += """
</body>
</html>
"""
    
    return html


def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description='Box FedRAMP Compliance Audit Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Run audit with text output
  %(prog)s --output-format json     Generate JSON report
  %(prog)s --output-format html     Generate HTML report
  %(prog)s --output report.html     Save report to file
  %(prog)s --config ~/box_jwt.json  Use specific Box config file
        """
    )
    
    parser.add_argument(
        '--config',
        help='Path to Box JWT config file (default: box_config.json or BOX_CONFIG_PATH env var)',
        default=None
    )
    
    parser.add_argument(
        '--output-format',
        choices=['text', 'json', 'html'],
        default='text',
        help='Output format for the report (default: text)'
    )
    
    parser.add_argument(
        '--output',
        help='Output file path (default: stdout)',
        default=None
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show all findings including low severity'
    )
    
    args = parser.parse_args()
    
    try:
        # Authenticate with Box
        logger.info("Authenticating with Box API...")
        authenticator = BoxAuthenticator(config_path=args.config)
        box_client = authenticator.authenticate()
        
        # Create API client wrapper
        api_client = BoxAPIClient(box_client)
        
        # Run compliance audit
        report = run_compliance_audit(api_client)
        
        # Generate report in requested format
        if args.output_format == 'json':
            output = generate_json_report(report)
        elif args.output_format == 'html':
            output = generate_html_report(report)
        else:
            output = generate_text_report(report)
        
        # Output report
        if args.output:
            output_path = Path(args.output)
            output_path.write_text(output)
            logger.info(f"Report saved to: {output_path}")
        else:
            print(output)
            
        # Exit with appropriate code
        if report.summary['critical_findings'] > 0:
            sys.exit(2)  # Critical findings
        elif report.summary['high_findings'] > 0:
            sys.exit(1)  # High findings
        else:
            sys.exit(0)  # Success
            
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(3)
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(4)


if __name__ == '__main__':
    main()