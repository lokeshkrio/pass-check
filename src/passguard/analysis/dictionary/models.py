from dataclasses import dataclass


@dataclass(slots=True, frozen=True)
class DictionaryMatchResult:
    word: str
    is_exact_match: bool
    start: int
    end: int
    rank: int | None = None
