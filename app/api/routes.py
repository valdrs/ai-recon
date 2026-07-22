from __future__ import annotations
import uuid
from datetime import datetime
from typing import Dict, List
from fastapi import APIRouter, HTTPException, Query
from app.models.schemas import (
    TargetRequest, ScanReport, RAGCitation, EnrichedVulnerability,
    ExecutiveSummary, SeverityLevel, SanitizedFinding
)
from app.recon.manager import recon_manager
from app.security.sanitization import banner_sanitizer
from app.rag.retriever import security_retriever
from app.rag.vector_store import vector_store
from app.ai.synthesizer import risk_synthesizer
from app.config import settings

router = APIRouter(prefix="/api/v1", tags=["Security Recon & AI Platform"])


@router.get("/health", summary="System Health & Status Check")
async def health_check():
    """Verify that the FastAPI server, FAISS vector store, and LLM provider are operational."""
    return {
        "status": "operational",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "active_llm_provider": settings.get_active_provider().value,
        "faiss_index_total_documents": vector_store.index.ntotal if vector_store.index else 0,
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/scan", response_model=ScanReport, summary="Initiate Attack Surface Scan & AI Synthesis")
async def start_scan(request: TargetRequest):
    """Run full reconnaissance, prompt injection sanitization, RAG enrichment, and AI risk synthesis."""
    start_time = datetime.utcnow()
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"

    try:
        # 1. Run Reconnaissance Enumeration
        raw_findings = await recon_manager.run_scan(request.target, request.modules)

        # 2. Apply Prompt Injection Defense & Sanitization
        sanitized_findings, sanitization_summary = banner_sanitizer.sanitize_findings_list(raw_findings)

        # 3. Perform RAG Vector Enrichment
        rag_citations_map: Dict[str, List[RAGCitation]] = {}
        for finding in sanitized_findings:
            cits = security_retriever.enrich_finding(finding)
            rag_citations_map[finding.finding_id] = cits

        # 4. Perform AI Risk Synthesis
        if request.enable_ai_synthesis:
            exec_summary, enriched_vulns = await risk_synthesizer.synthesize(
                target=request.target,
                sanitized_findings=sanitized_findings,
                rag_citations=rag_citations_map
            )
        else:
            # Fallback when AI synthesis explicitly disabled
            exec_summary = ExecutiveSummary(
                overall_risk_score=5.0,
                risk_tier=SeverityLevel.MEDIUM,
                summary_text=f"Raw scan completed across {request.target}. AI synthesis was disabled.",
                key_attack_vectors=[],
                critical_recommendations=[]
            )
            enriched_vulns = [
                EnrichedVulnerability(
                    vulnerability_id=f.finding_id,
                    title=f.title,
                    severity=SeverityLevel.MEDIUM,
                    cvss_estimate=5.0,
                    affected_service=f"{f.module.value}:{f.port or 'general'}",
                    description=f.description,
                    technical_impact="Review raw evidence for exact impact.",
                    mitre_mappings=[],
                    rag_citations=rag_citations_map.get(f.finding_id, []),
                    remediation_steps=[]
                )
                for f in sanitized_findings
            ]

        end_time = datetime.utcnow()

        return ScanReport(
            scan_id=scan_id,
            target=request.target,
            scan_type=request.scan_type,
            scan_started_at=start_time,
            scan_completed_at=end_time,
            status="completed",
            llm_provider_used=settings.get_active_provider().value,
            sanitization_summary=sanitization_summary,
            executive_summary=exec_summary,
            vulnerabilities=enriched_vulns,
            raw_findings_count=len(raw_findings)
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan pipeline execution error: {str(e)}")


@router.get("/rag/search", summary="Search FAISS Cybersecurity Knowledge Base")
async def search_rag_knowledge(
    query: str = Query(..., description="Vulnerability query, MITRE technique, or keyword (e.g., 'OpenSSH' or 'T1190')"),
    top_k: int = Query(default=4, ge=1, le=10, description="Number of vector citations to return")
):
    """Direct semantic search against the FAISS knowledge store."""
    results = vector_store.search(query, top_k=top_k)
    return {
        "query": query,
        "results_count": len(results),
        "citations": results
    }
