import os
from typing import Dict, Any, List
from models.vulnerability import Vulnerability, SeverityLevel
from models.report import PentestSummary
from config import REPORT_OUTPUT_DIR

def generate_finding_report(vuln_data: Dict[str, Any]) -> str:
    """Generate a structured Markdown report for a single finding."""
    try:
        vuln = Vulnerability(**vuln_data)
    except Exception as e:
        return f"Error creating vulnerability report: {str(e)}"

    md_content = f"# {vuln.title}\n\n"

    md_content += f"**Severity:** {vuln.severity.value}\n"
    md_content += f"**Type:** {vuln.type.value}\n"
    if vuln.cvss_score:
        md_content += f"**CVSS:** {vuln.cvss_score}\n"
    md_content += f"**Target:** {vuln.target_url}\n"
    if vuln.parameter:
        md_content += f"**Parameter:** {vuln.parameter}\n"
    md_content += "\n"
    
    md_content += "## Description\n"
    md_content += f"{vuln.description}\n\n"
    
    md_content += "## Evidence\n"
    md_content += f"```http\n{vuln.evidence}\n```\n\n"
    
    md_content += "## Remediation\n"
    md_content += f"{vuln.remediation}\n\n"

    if vuln.references:
        md_content += "## References\n"
        for ref in vuln.references:
            md_content += f"- {ref}\n"
    
    # Save to file
    filename = f"{vuln.title.replace(' ', '_').lower()}.md"
    filepath = os.path.join(REPORT_OUTPUT_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    return f"Report generated and saved to {filepath}"

def export_findings(findings: List[Dict[str, Any]], project_name: str) -> str:
    """Export all findings into an executive summary."""
    try:
        vuln_objects = [Vulnerability(**f) for f in findings]
    except Exception as e:
        return f"Error parsing findings: {str(e)}"
    
    summary = PentestSummary(
        project_name=project_name,
        total_findings=len(vuln_objects),
        findings=vuln_objects
    )
    
    # Fix: Compare using Enum values, not string literals
    for v in vuln_objects:
        if v.severity == SeverityLevel.CRITICAL: summary.critical_count += 1
        elif v.severity == SeverityLevel.HIGH: summary.high_count += 1
        elif v.severity == SeverityLevel.MEDIUM: summary.medium_count += 1
        elif v.severity == SeverityLevel.LOW: summary.low_count += 1
        elif v.severity == SeverityLevel.INFORMATIONAL: summary.info_count += 1

    filepath = os.path.join(REPORT_OUTPUT_DIR, f"{project_name}_summary.json")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(summary.model_dump_json(indent=2))
        
    return f"Summary exported to {filepath}"

