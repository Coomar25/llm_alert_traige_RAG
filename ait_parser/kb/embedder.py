"""
Embedding wrapper around sentence-transformers/all-MiniLM-L6-v2.

Why all-MiniLM-L6-v2?
    - 384-dimensional output (small vectors → fast similarity search)
    - 22M parameters (CPU-friendly, no GPU required)
    - Pre-trained on 1B+ sentence pairs, strong general-purpose retrieval
    - Standard choice in the RAG literature — easy to defend in viva

The model is downloaded once (~80MB) and cached by sentence-transformers
under ~/.cache/torch/sentence_transformers/.

We batch embeddings to amortise model overhead. 64 is a safe batch size
for CPU; if you have a GPU, sentence-transformers will auto-detect and
use it.
"""

from typing import List

# Lazy import — sentence-transformers is heavy; only load when needed.
_model = None


def _get_model(model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
    """Load the embedding model once and cache it in module state."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer  # type: ignore
        print(f"  Loading embedding model: {model_name}")
        _model = SentenceTransformer(model_name)
        print(f"  Model loaded. Embedding dim: {_model.get_sentence_embedding_dimension()}")
    return _model


def embed_texts(texts: List[str], batch_size: int = 64) -> List[List[float]]:
    """Embed a list of texts and return list-of-list-of-floats for ChromaDB."""
    if not texts:
        return []
    model = _get_model()
    vectors = model.encode(
        texts,
        batch_size=batch_size,
        show_progress_bar=len(texts) > 100,
        convert_to_numpy=True,
        normalize_embeddings=True,  # cosine similarity becomes a dot product
    )
    # ChromaDB wants list-of-floats, not numpy
    return [v.tolist() for v in vectors]


def embedding_dim() -> int:
    """Return the embedding dimensionality. Useful for ChromaDB collection setup."""
    return _get_model().get_sentence_embedding_dimension()
