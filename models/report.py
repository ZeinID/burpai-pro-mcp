from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from .vulnerability import Vulnerability, SeverityLevel

class FindingReport(BaseModel):
    """Detailed report for a single finding."""
    finding: Vulnerability
    reported_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    status: str = Field(default="Open", description="Status of the finding (Open, Confirmed, Remediated)")
    notes: Optional[str] = Field(default=None, description="Additional notes from the tester")

class PentestSummary(BaseModel):
    """Executive summary of the penetration test."""
    project_name: str = Field(default="BurpAI Pro Pentest", description="Name of the project/target")
    date_generated: str = Field(default_factory=lambda: datetime.now().isoformat())
    total_findings: int = Field(default=0)
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    info_count: int = Field(default=0)
    findings: List[Vulnerability] = Field(default_factory=list)
    executive_summary: str = Field(default="No summary provided.", description="High-level overview of the security posture")
