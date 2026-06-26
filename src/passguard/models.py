from dataclasses import dataclass, field
from enum import Enum
from passguard.analysis.pattern.models import PatternResult
from passguard.analysis.dictionary.models import DictionaryMatchResult


@dataclass(slots=True, frozen=True)
class CharacterAnalysis:
    length: int
    lowercase: int
    uppercase: int
    digits: int
    symbols: int
    whitespace: int
    unicode: int


@dataclass(slots=True, frozen=True)
class Recommendation:
    severity: str
    message: str


@dataclass(slots=True, frozen=True)
class EntropyResult:
    theoretical_bits: float
    effective_bits: float
    charset_size: int


@dataclass(slots=True, frozen=True)
class ScoreResult:
    score: int
    strength: "Strength"


@dataclass(slots=True, frozen=True)
class PasswordReport:
    score: int
    strength: str

    characters: CharacterAnalysis
    entropy: EntropyResult

    recommendations: list[Recommendation]
    patterns: PatternResult | None = None
    dictionary_matches: list[DictionaryMatchResult] = field(default_factory=list)
    crack_times: dict[str, float] = field(default_factory=dict)


class Strength(Enum):
    VERY_WEAK = "Very Weak"
    WEAK = "Weak"
    MODERATE = "Moderate"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"
