from passguard.analysis.pattern.repeated import (
    RepeatedCharacterDetector,
    RepeatedSubstringDetector,
)
from passguard.analysis.pattern.sequence import SequenceDetector
from passguard.analysis.pattern.keyboard import KeyboardWalkDetector
from passguard.context import AnalysisContext


class PatternAnalyzer:
    def __init__(self) -> None:
        self.repeated = RepeatedCharacterDetector()
        self.repeated_substrings = RepeatedSubstringDetector()
        self.sequence = SequenceDetector()
        self.keyboard = KeyboardWalkDetector()

    def analyze(self, context: AnalysisContext) -> None:
        self.repeated.analyze(context)
        self.repeated_substrings.analyze(context)
        self.sequence.analyze(context)
        self.keyboard.analyze(context)
