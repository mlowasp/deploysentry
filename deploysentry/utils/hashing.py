from __future__ import annotations
import hashlib
import re


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body[:200_000]).hexdigest()


def normalize_body_for_similarity(text: str) -> str:
    text = re.sub(r"\d+", "0", text.lower())
    text = re.sub(r"[a-f0-9]{16,}", "hex", text)
    text = re.sub(r"\s+", " ", text)
    return text[:4000]


def similarity(a: str, b: str) -> float:
    # Lightweight token Jaccard. Good enough for soft-404 comparisons.
    sa = set(normalize_body_for_similarity(a).split())
    sb = set(normalize_body_for_similarity(b).split())
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / max(1, len(sa | sb))
