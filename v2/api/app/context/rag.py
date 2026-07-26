"""
================================================================================
AEGIS AI v2 - RAG Knowledge Base
================================================================================

Module      : rag.py
Description : Retrieval-Augmented Generation layer. Indexes evaluation
              reports and the attack reference document, providing
              grounded context retrieval for the Agent's reasoning.

              Uses FastEmbed (ONNX runtime) instead of sentence-transformers
              (PyTorch) for embeddings — dramatically lower memory footprint,
              needed to fit within Render's 512MB free-tier limit alongside
              the ML ensemble.
Author      : Prerak Nain
================================================================================
"""

from pathlib import Path
from typing import List

from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import FastEmbedEmbeddings
from langchain_community.vectorstores import Chroma


class Config:
    # Resolve relative to this file's location so it works both locally
    # and inside Docker, regardless of the working directory.
    _CONTEXT_DIR = Path(__file__).resolve().parent  # .../app/context
    _APP_DIR = _CONTEXT_DIR.parent                   # .../app
    _API_DIR = _APP_DIR.parent                        # .../api

    RESULTS_DIR = _API_DIR / "results"
    CHROMA_DIR = _CONTEXT_DIR / "chroma_db"

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
    """Retrieval layer over Aegis AI's knowledge base."""

    def __init__(self):
        self.embeddings = FastEmbedEmbeddings(model_name=Config.EMBEDDING_MODEL)
        self.vectorstore = self._load_or_build_index()

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

    def _load_or_build_index(self) -> Chroma:
        if Config.CHROMA_DIR.exists() and any(Config.CHROMA_DIR.iterdir()):
            print("[RAG] Loading existing index...")
            return Chroma(
                persist_directory=str(Config.CHROMA_DIR),
                embedding_function=self.embeddings,
            )

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
        chunks = splitter.split_documents(raw_docs)
        print(f"[RAG] Split into {len(chunks)} chunks")

        Config.CHROMA_DIR.mkdir(parents=True, exist_ok=True)
        vectorstore = Chroma.from_documents(
            documents=chunks,
            embedding=self.embeddings,
            persist_directory=str(Config.CHROMA_DIR),
        )
        print("[RAG] Index built and persisted.")
        return vectorstore

    def retrieve(self, query: str, k: int = 3) -> List[str]:
        """Return the top-k most relevant chunks of text for a query."""
        results = self.vectorstore.similarity_search(query, k=k)
        return [doc.page_content for doc in results]


# ==============================================================================
# SINGLETON — load once, reuse everywhere (avoids reloading the embedding
# model + Chroma index on every single agent call)
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