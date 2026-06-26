from __future__ import annotations
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from passguard.analysis.pattern.models import PatternFinding
    from passguard.analysis.dictionary.models import DictionaryMatchResult
    from passguard.models import (
        CharacterAnalysis,
        EntropyResult,
        ScoreResult,
        Recommendation,
    )


@dataclass(slots=True)
class AnalysisContext:
    password: str

    characters: CharacterAnalysis | None = None
    entropy: EntropyResult | None = None
    score: ScoreResult | None = None
    patterns: list[PatternFinding] = field(default_factory=list)
    pattern_penalty_bits: float = 0.0
    normalized_passwords: list[str] = field(default_factory=list)
    dictionary_matches: list[DictionaryMatchResult] = field(default_factory=list)
    crack_times: dict[str, float] = field(default_factory=dict)
    recommendations: list[Recommendation] = field(default_factory=list)

    def require_characters(self) -> CharacterAnalysis:
        if self.characters is None:
            raise RuntimeError("Character analysis has not been run.")
        return self.characters

    def require_entropy(self) -> EntropyResult:
        if self.entropy is None:
            raise RuntimeError("Entropy analysis has not been run.")
        return self.entropy

    def require_score(self) -> ScoreResult:
        if self.score is None:
            raise RuntimeError("Score analysis has not been run.")
        return self.score
