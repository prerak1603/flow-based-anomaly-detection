"""
================================================================================
AEGIS AI v2 - RAG Knowledge Base
================================================================================

Module      : rag.py
Description : Retrieval-Augmented Generation layer. Indexes evaluation
              reports and the attack reference document, providing
              grounded context retrieval for the Agent's reasoning.

              Uses FastEmbed (ONNX runtime, no PyTorch) for embeddings and
              a simple in-memory NumPy similarity search instead of a full
              vector database. The knowledge base is ~32 small chunks — a
              database engine (Chroma) adds meaningful memory overhead for
              a corpus this size with no real benefit. This combination was
              needed to fit within Render's 512MB free-tier memory limit
              alongside the ML ensemble.
Author      : Prerak Nain
================================================================================
"""

import pickle
from pathlib import Path
from typing import List

import numpy as np
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import FastEmbedEmbeddings


class Config:
    # Resolve relative to this file's location so it works both locally
    # and inside Docker, regardless of the working directory.
    _CONTEXT_DIR = Path(__file__).resolve().parent  # .../app/context
    _APP_DIR = _CONTEXT_DIR.parent                   # .../app
    _API_DIR = _APP_DIR.parent                        # .../api

    RESULTS_DIR = _API_DIR / "results"
    INDEX_FILE = _CONTEXT_DIR / "rag_index.pkl"

    SOURCE_DOCUMENTS = [
        RESULTS_DIR / "attack_reference.txt",
        RESULTS_DIR / "day1_evaluation_report.txt",
        RESULTS_DIR / "day2_smote_report.txt",
        RESULTS_DIR / "lightgbm_best_params.txt",
    ]

    # Small, ONNX-based embedding model — no PyTorch dependency,
    # low memory footprint, well suited for constrained deployments.
    EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"
    CHUNK_SIZE = 500
    CHUNK_OVERLAP = 50


class AegisRAG:
    """
    Retrieval layer over Aegis AI's knowledge base.

    Uses a plain in-memory NumPy array for similarity search — appropriate
    for a small, static corpus (tens of chunks), avoiding the overhead of
    a full vector database.
    """

    def __init__(self):
        self.embeddings = FastEmbedEmbeddings(model_name=Config.EMBEDDING_MODEL)
        self.chunks: List[str] = []
        self.vectors: np.ndarray = None
        self._load_or_build_index()

    def _load_documents(self) -> List:
        docs = []
        for path in Config.SOURCE_DOCUMENTS:
            if path.exists():
                loader = TextLoader(str(path))
                docs.extend(loader.load())
                print(f"[RAG] Loaded: {path.name}")
            else:
                print(f"[RAG] Skipped (not found): {path.name}")
        return docs

    def _load_or_build_index(self):
        if Config.INDEX_FILE.exists():
            print("[RAG] Loading existing index...")
            with open(Config.INDEX_FILE, "rb") as f:
                data = pickle.load(f)
            self.chunks = data["chunks"]
            self.vectors = data["vectors"]
            print(f"[RAG] Loaded {len(self.chunks)} chunks from disk.")
            return

        print("[RAG] Building new index...")
        raw_docs = self._load_documents()

        if not raw_docs:
            raise RuntimeError(
                "No source documents found. Check Config.SOURCE_DOCUMENTS paths."
            )

        splitter = RecursiveCharacterTextSplitter(
            chunk_size=Config.CHUNK_SIZE,
            chunk_overlap=Config.CHUNK_OVERLAP,
        )
        split_docs = splitter.split_documents(raw_docs)
        self.chunks = [doc.page_content for doc in split_docs]
        print(f"[RAG] Split into {len(self.chunks)} chunks")

        print("[RAG] Computing embeddings...")
        raw_vectors = self.embeddings.embed_documents(self.chunks)
        self.vectors = np.array(raw_vectors, dtype=np.float32)

        # Persist to disk so future startups skip re-embedding
        with open(Config.INDEX_FILE, "wb") as f:
            pickle.dump({"chunks": self.chunks, "vectors": self.vectors}, f)

        print("[RAG] Index built and persisted.")

    def retrieve(self, query: str, k: int = 3) -> List[str]:
        """Return the top-k most relevant chunks of text for a query."""
        if self.vectors is None or len(self.chunks) == 0:
            return []

        query_vector = np.array(self.embeddings.embed_query(query), dtype=np.float32)

        # Cosine similarity: dot product of normalized vectors
        query_norm = query_vector / (np.linalg.norm(query_vector) + 1e-9)
        chunk_norms = self.vectors / (
            np.linalg.norm(self.vectors, axis=1, keepdims=True) + 1e-9
        )
        similarities = chunk_norms @ query_norm

        top_k_indices = np.argsort(similarities)[::-1][:k]
        return [self.chunks[i] for i in top_k_indices]


# ==============================================================================
# SINGLETON — load once, reuse everywhere (avoids reloading the embedding
# model + index on every single agent call)
# ==============================================================================

_rag_instance = None


def get_rag() -> AegisRAG:
    """Return the shared AegisRAG instance, creating it on first call."""
    global _rag_instance
    if _rag_instance is None:
        print("[RAG] Initializing shared instance (first call)...")
        _rag_instance = AegisRAG()
    return _rag_instance


# ==============================================================================
# QUICK STANDALONE TEST
# ==============================================================================

if __name__ == "__main__":
    rag = get_rag()

    test_queries = [
        "Why does DDoS have high precision in evaluation?",
        "What is the intent behind a DoS slowloris attack?",
        "Why did Heartbleed have low recall originally?",
    ]

    for q in test_queries:
        print(f"\n{'='*70}\nQUERY: {q}\n{'='*70}")
        for i, chunk in enumerate(rag.retrieve(q, k=2)):
            print(f"\n[Result {i+1}]\n{chunk[:300]}...")