from dataclasses import dataclass, field
from passguard.analysis.pattern.models import PatternFinding
from passguard.models import CharacterAnalysis, EntropyResult


@dataclass(slots=True)
class AnalysisContext:
    password: str

    characters: CharacterAnalysis | None = None
    entropy: EntropyResult | None = None
    patterns: list[PatternFinding] = field(default_factory=list)
    pattern_penalty_bits: float = 0.0

    def require_characters(self) -> CharacterAnalysis:
        if self.characters is None:
            raise RuntimeError("Character analysis has not been run.")
        return self.characters

    def require_entropy(self) -> EntropyResult:
        if self.entropy is None:
            raise RuntimeError("Entropy analysis has not been run.")
        return self.entropy
