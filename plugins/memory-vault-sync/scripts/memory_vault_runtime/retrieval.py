"""Versioned, deterministic local retrieval adapters.

The adapter in this module is derived local state only.  It performs no I/O,
uses no model or provider, and keeps lexical retrieval independently usable.
"""

from __future__ import annotations

import dataclasses
import re
import unicodedata
from typing import AbstractSet, Mapping


SEMANTIC_ADAPTER_ID = "deterministic-concepts-v1"
_LATIN_WORD_RE = re.compile(r"[a-z0-9][a-z0-9_+.-]{1,63}")
_SPACE_RE = re.compile(r"\s+")
_NEGATIVE_FEATURE = "polarity:negative"

_CONCEPT_GROUPS = (
    frozenset({"备份", "保存", "存档", "backup", "archive", "save"}),
    frozenset({"同步", "传输", "复制", "sync", "transfer", "replicate"}),
    frozenset(
        {
            "快速",
            "高效",
            "性能",
            "等待",
            "延迟",
            "fast",
            "efficient",
            "latency",
            "performance",
        }
    ),
    frozenset({"记忆", "回忆", "召回", "memory", "recall", "remember"}),
    frozenset({"删除", "移除", "清理", "delete", "remove", "cleanup"}),
    frozenset({"冲突", "矛盾", "不一致", "conflict", "contradiction"}),
    frozenset({"偏好", "喜欢", "习惯", "preference", "prefer"}),
    frozenset({"更正", "纠正", "修正", "correction", "correct", "fix"}),
    frozenset({"本地", "离线", "设备", "local", "offline", "device"}),
    frozenset({"加密", "隐私", "安全", "encrypt", "privacy", "secure"}),
)
_NEGATION_MARKERS = frozenset(
    {
        "不",
        "不要",
        "无需",
        "无须",
        "没有",
        "不能",
        "禁止",
        "not",
        "never",
        "without",
        "no",
    }
)


def _normalize(value: str) -> str:
    return _SPACE_RE.sub(
        " ", unicodedata.normalize("NFKC", value).casefold()
    ).strip()


def _contains_term(normalized: str, latin_words: set[str], term: str) -> bool:
    """Match CJK phrases as text and Latin concepts as complete words."""

    if term.isascii():
        return term in latin_words
    return term in normalized


@dataclasses.dataclass(frozen=True)
class DeterministicSemanticAdapter:
    """Small explainable cross-language feature adapter with stable identity."""

    adapter_id: str = SEMANTIC_ADAPTER_ID

    def features(self, value: str) -> frozenset[str]:
        if not isinstance(value, str):
            raise TypeError("semantic retrieval input must be text")
        normalized = _normalize(value)
        latin_words = set(_LATIN_WORD_RE.findall(normalized))
        features: set[str] = set()
        for index, group in enumerate(_CONCEPT_GROUPS):
            if any(
                _contains_term(normalized, latin_words, term)
                for term in group
            ):
                features.add(f"concept:{index}")
        if any(
            _contains_term(normalized, latin_words, marker)
            for marker in _NEGATION_MARKERS
        ):
            features.add(_NEGATIVE_FEATURE)
        return frozenset(features)

    def similarity(
        self,
        query_features: AbstractSet[str],
        fragment_features: AbstractSet[str],
    ) -> float:
        """Return concept Jaccard with a deterministic polarity penalty."""

        query_concepts = {
            item for item in query_features if item.startswith("concept:")
        }
        fragment_concepts = {
            item for item in fragment_features if item.startswith("concept:")
        }
        overlap = query_concepts & fragment_concepts
        if not overlap:
            return 0.0
        score = len(overlap) / len(query_concepts | fragment_concepts)
        if (_NEGATIVE_FEATURE in query_features) != (
            _NEGATIVE_FEATURE in fragment_features
        ):
            score *= 0.25
        return score

    def candidate_terms(
        self,
        query_features: AbstractSet[str],
    ) -> Mapping[str, tuple[str, ...]]:
        """Return stable synonym terms for full-index candidate expansion."""

        result: dict[str, tuple[str, ...]] = {}
        for feature in sorted(query_features):
            if not feature.startswith("concept:"):
                continue
            try:
                index = int(feature.removeprefix("concept:"))
                group = _CONCEPT_GROUPS[index]
            except (ValueError, IndexError):
                continue
            result[feature] = tuple(sorted(group))
        return result


LOCAL_SEMANTIC_ADAPTER = DeterministicSemanticAdapter()
