from passguard.analysis.pattern.repeated import (
    RepeatedCharacterDetector,
    RepeatedSubstringDetector,
)
from passguard.context import AnalysisContext


class PatternAnalyzer:

    def __init__(self) -> None:
        self.repeated = RepeatedCharacterDetector()
        self.repeated_substrings = RepeatedSubstringDetector()

    def analyze(self, context: AnalysisContext) -> None:
        self.repeated.analyze(context)
        self.repeated_substrings.analyze(context)
