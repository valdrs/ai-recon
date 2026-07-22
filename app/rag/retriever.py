from __future__ import annotations
from typing import List, Optional
from app.models.schemas import SanitizedFinding, RAGCitation
from app.rag.vector_store import vector_store
from app.config import settings


class SecurityRetriever:
    """Retrieves relevant vulnerability definitions and MITRE ATT&CK citations for findings."""

    @classmethod
    def enrich_finding(cls, finding: SanitizedFinding, top_k: Optional[int] = None) -> List[RAGCitation]:
        """Perform semantic retrieval against FAISS using the finding's clean title and evidence."""
        k = top_k if top_k is not None else settings.RAG_TOP_K

        # Build query string combining title, module, protocol, and clean evidence
        query = f"{finding.title} {finding.module.value} {finding.protocol or ''} {finding.evidence_clean[:200]}"
        raw_results = vector_store.search(query, top_k=k)

        citations = []
        for res in raw_results:
            citations.append(
                RAGCitation(
                    doc_id=res["doc_id"],
                    category=res["category"],
                    title=res["title"],
                    content=res["content"],
                    similarity_score=res["similarity_score"]
                )
            )

        return citations


security_retriever = SecurityRetriever()
