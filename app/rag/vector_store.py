from __future__ import annotations
import numpy as np
import faiss
from typing import Any, List, Dict, Optional
from app.rag.knowledge_base import SECURITY_KNOWLEDGE_BASE
from app.config import settings


class FAISSVectorStore:
    """FAISS Vector Database wrapper supporting embeddings or lightweight fallback vectorization."""

    def __init__(self):
        self.documents = SECURITY_KNOWLEDGE_BASE
        self.index: Optional[Any] = None
        self.encoder = None
        self.embedding_dim = 384  # Default MiniLM or fallback dim
        self._initialize_encoder_and_index()

    def _fallback_embed(self, texts: List[str]) -> np.ndarray:
        """Lightweight deterministic TF-IDF/hashed n-gram embedding fallback when model loading is skipped."""
        embeddings = np.zeros((len(texts), self.embedding_dim), dtype=np.float32)
        for i, text in enumerate(texts):
            # Generate deterministic token buckets across embedding_dim
            words = text.lower().replace(":", " ").replace("/", " ").replace("-", " ").split()
            for j, word in enumerate(words):
                bucket = hash(word) % self.embedding_dim
                embeddings[i, bucket] += 1.0 + (1.0 / (j + 1.0))
            # Normalize to unit vector for cosine similarity (Inner Product)
            norm = np.linalg.norm(embeddings[i])
            if norm > 0:
                embeddings[i] /= norm
        return embeddings

    def _initialize_encoder_and_index(self):
        """Try loading sentence-transformers or use high-speed fallback for instant initialization."""
        try:
            from sentence_transformers import SentenceTransformer
            # Try lightweight model loading with short timeout/cached check
            self.encoder = SentenceTransformer(settings.EMBEDDING_MODEL_NAME)
            self.embedding_dim = self.encoder.get_sentence_embedding_dimension()
            print(f"[RAG] Successfully loaded SentenceTransformer ({settings.EMBEDDING_MODEL_NAME})")
        except Exception as e:
            print(f"[RAG] SentenceTransformer not loaded ({str(e)[:40]}). Using instant high-speed fallback vectorizer.")
            self.encoder = None
            self.embedding_dim = 384

        # Build FAISS Index (Inner Product for normalized vectors = Cosine Similarity)
        self.index = faiss.IndexFlatIP(self.embedding_dim)

        # Index all documents
        doc_texts = [
            f"{doc['title']} {doc['category']} {doc.get('tactic', '')} {doc['content']}"
            for doc in self.documents
        ]
        
        if self.encoder:
            embeddings = self.encoder.encode(doc_texts, convert_to_numpy=True, normalize_embeddings=True)
        else:
            embeddings = self._fallback_embed(doc_texts)

        self.index.add(embeddings)
        print(f"[RAG] FAISS Index built successfully with {self.index.ntotal} security documents.")

    def search(self, query_text: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Query the FAISS vector index and retrieve top-k similar knowledge documents."""
        if not self.index or self.index.ntotal == 0:
            return []

        if self.encoder:
            query_vector = self.encoder.encode([query_text], convert_to_numpy=True, normalize_embeddings=True)
        else:
            query_vector = self._fallback_embed([query_text])

        scores, indices = self.index.search(query_vector, min(top_k, len(self.documents)))

        results = []
        for rank, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self.documents):
                score = float(scores[0][rank])
                if score >= settings.SIMILARITY_THRESHOLD:
                    doc = self.documents[idx].copy()
                    doc["similarity_score"] = round(score, 3)
                    results.append(doc)

        return results


# Global singleton instance
vector_store = FAISSVectorStore()
