"""
================================================================================
AEGIS AI v2 - RAG Knowledge Base
================================================================================

Module      : rag.py
Description : Retrieval-Augmented Generation layer. Indexes evaluation
              reports and the attack reference document, providing
              grounded context retrieval for the Agent's reasoning.

              Uses TF-IDF (scikit-learn) instead of neural embeddings.
              Even fastembed's ONNX model, loaded alongside the ML ensemble,
              exceeded Render's 512MB free-tier limit. For a small (~32
              chunk), vocabulary-distinctive corpus — attack names like
              "DDoS" or "Heartbleed" appear near-verbatim in both documents
              and queries — TF-IDF keyword matching is a reasonable
              trade-off: no neural model loaded at all, using scikit-learn,
              which is already a dependency for the ML ensemble.
Author      : Prerak Nain
================================================================================
"""

import pickle
from pathlib import Path
from typing import List

from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


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

    CHUNK_SIZE = 500
    CHUNK_OVERLAP = 50


class AegisRAG:
    """
    Retrieval layer over Aegis AI's knowledge base.

    Uses TF-IDF keyword-based similarity rather than neural embeddings —
    no model to load into memory, appropriate for a small, vocabulary-
    distinctive corpus under real memory constraints.
    """

    def __init__(self):
        self.vectorizer: TfidfVectorizer = None
        self.chunks: List[str] = []
        self.chunk_vectors = None
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
            self.vectorizer = data["vectorizer"]
            self.chunk_vectors = data["chunk_vectors"]
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

        print("[RAG] Fitting TF-IDF vectorizer...")
        self.vectorizer = TfidfVectorizer(stop_words="english", max_features=2000)
        self.chunk_vectors = self.vectorizer.fit_transform(self.chunks)

        with open(Config.INDEX_FILE, "wb") as f:
            pickle.dump(
                {
                    "chunks": self.chunks,
                    "vectorizer": self.vectorizer,
                    "chunk_vectors": self.chunk_vectors,
                },
                f,
            )

        print("[RAG] Index built and persisted.")

    def retrieve(self, query: str, k: int = 3) -> List[str]:
        """Return the top-k most relevant chunks of text for a query."""
        if self.vectorizer is None or len(self.chunks) == 0:
            return []

        query_vector = self.vectorizer.transform([query])
        similarities = cosine_similarity(query_vector, self.chunk_vectors)[0]

        top_k_indices = similarities.argsort()[::-1][:k]
        return [self.chunks[i] for i in top_k_indices]


# ==============================================================================
# SINGLETON — load once, reuse everywhere
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