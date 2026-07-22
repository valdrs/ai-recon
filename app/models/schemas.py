from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union, List, Dict
from pydantic import BaseModel, Field


class ScanType(str, Enum):
    QUICK = "quick"         # Top ports + basic headers + basic DNS
    FULL = "full"           # Extended ports + comprehensive headers + SSL check + DNS enumeration
    CUSTOM = "custom"       # User selected modules


class ScannerModule(str, Enum):
    DNS = "dns"
    PORT = "port"
    WEB_HEADERS = "web_headers"


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class TargetRequest(BaseModel):
    """Input request model to initiate an attack surface scan."""
    target: str = Field(..., description="Target domain, hostname, or IP address (e.g., 'scanme.nmap.org' or 'localhost')", example="scanme.nmap.org")
    scan_type: ScanType = Field(default=ScanType.QUICK, description="Scan profile depth")
    modules: Optional[List[ScannerModule]] = Field(
        default=[ScannerModule.DNS, ScannerModule.PORT, ScannerModule.WEB_HEADERS],
        description="Modules to run if scan_type is custom"
    )
    enable_ai_synthesis: bool = Field(default=True, description="Enrich results using RAG + LLM analysis")


class RawFinding(BaseModel):
    """A raw discovery produced by a reconnaissance module before sanitization/enrichment."""
    finding_id: str = Field(..., description="Unique identifier for this finding")
    module: ScannerModule = Field(..., description="Scanner module that discovered this item")
    title: str = Field(..., description="Short descriptive title of discovery")
    description: str = Field(..., description="Detailed technical output or banner")
    raw_evidence: Union[str, Dict[str, Any]] = Field(..., description="Raw string or dictionary evidence grabbed from target")
    port: Optional[int] = Field(default=None, description="Associated port number if applicable")
    protocol: Optional[str] = Field(default=None, description="Transport or application protocol (e.g., 'tcp/ssh', 'https')")
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SanitizedFinding(BaseModel):
    """A finding that has passed through prompt injection defense and input sanitization."""
    finding_id: str
    module: ScannerModule
    title: str
    description: str
    evidence_clean: str = Field(..., description="Sanitized evidence string safe for RAG query and LLM context")
    port: Optional[int] = None
    protocol: Optional[str] = None
    sanitization_flags: List[str] = Field(
        default_factory=list,
        description="List of security alterations made (e.g., 'REMOVED_ANOMALOUS_PROMPT_TAGS')"
    )


class RAGCitation(BaseModel):
    """Context retrieved from the FAISS knowledge store."""
    doc_id: str = Field(..., description="Unique ID in the knowledge base (CVE, MITRE ID, OWASP Item)")
    category: str = Field(..., description="Category (e.g., 'MITRE_ATTACK', 'CVE', 'OWASP_TOP_10', 'REMEDIATION_GUIDE')")
    title: str = Field(..., description="Title of the knowledge document")
    content: str = Field(..., description="Text excerpt or vulnerability definition retrieved")
    similarity_score: float = Field(..., description="Cosine or L2 similarity score from vector search")


class MITRETechnique(BaseModel):
    """Structured MITRE ATT&CK mapping."""
    technique_id: str = Field(..., description="MITRE Technique ID (e.g., 'T1190')")
    technique_name: str = Field(..., description="Name (e.g., 'Exploit Public-Facing Application')")
    tactic: str = Field(..., description="Associated Tactic (e.g., 'Initial Access')")
    description: str = Field(..., description="Brief explanation of how this applies to the finding")


class EnrichedVulnerability(BaseModel):
    """Fully analyzed finding with risk score, RAG context, MITRE mapping, and remediation steps."""
    vulnerability_id: str
    title: str
    severity: SeverityLevel
    cvss_estimate: float = Field(..., ge=0.0, le=10.0, description="Estimated CVSS base score")
    affected_service: str = Field(..., description="Service name/port associated")
    description: str
    technical_impact: str = Field(..., description="Potential impact if exploited")
    mitre_mappings: List[MITRETechnique] = Field(default_factory=list)
    rag_citations: List[RAGCitation] = Field(default_factory=list)
    remediation_steps: List[str] = Field(
        default_factory=list,
        description="Actionable, step-by-step guidance to secure this vector"
    )


class ExecutiveSummary(BaseModel):
    """High-level AI synthesized overview of the target's attack surface posture."""
    overall_risk_score: float = Field(..., ge=0.0, le=10.0, description="Aggregate security risk score (0=Secure, 10=Critical)")
    risk_tier: SeverityLevel = Field(..., description="Overall risk classification")
    summary_text: str = Field(..., description="Plain-English summary suitable for executives and security architects")
    key_attack_vectors: List[str] = Field(default_factory=list, description="Top identified paths of entry or exposure")
    critical_recommendations: List[str] = Field(default_factory=list, description="Immediate priority actions required")


class ScanReport(BaseModel):
    """Complete, end-to-end report generated for a target scan."""
    scan_id: str = Field(..., description="Unique scan session ID")
    target: str = Field(..., description="Target scanned")
    scan_type: ScanType
    scan_started_at: datetime
    scan_completed_at: datetime
    status: str = Field(default="completed", description="Scan execution status")
    llm_provider_used: str = Field(..., description="LLM provider utilized for analysis (or 'mock')")
    sanitization_summary: Dict[str, Any] = Field(
        default_factory=dict,
        description="Metrics on prompt injection defense actions applied during scan"
    )
    executive_summary: ExecutiveSummary
    vulnerabilities: List[EnrichedVulnerability] = Field(default_factory=list)
    raw_findings_count: int = 0
