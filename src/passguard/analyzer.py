from passguard.analysis.charset import CharacterAnalyzer
from passguard.analysis.effective_entropy import EffectiveEntropyAnalyzer
from passguard.analysis.entropy import EntropyAnalyzer
from passguard.analysis.pattern.engine import PatternAnalyzer
from passguard.analysis.pattern.models import PatternResult
from passguard.context import AnalysisContext
from passguard.exceptions import InvalidPasswordError
from passguard.models import PasswordReport


class PasswordAnalyzer:

    def __init__(self) -> None:
        self.character = CharacterAnalyzer()
        self.entropy = EntropyAnalyzer()
        self.pattern = PatternAnalyzer()
        self.effective_entropy = EffectiveEntropyAnalyzer()

    def analyze(self, password: str) -> PasswordReport:

        if not isinstance(password, str):
            raise InvalidPasswordError("Password must be a string.")

        context = AnalysisContext(password=password)

        self.character.analyze(context)
        self.entropy.analyze(context)
        self.pattern.analyze(context)
        self.effective_entropy.analyze(context)

        return PasswordReport(
            score=0,
            strength="Unknown",
            characters=context.require_characters(),
            entropy=context.require_entropy(),
            recommendations=[],
            patterns=(
                PatternResult(
                    findings=context.patterns,
                    penalty=context.pattern_penalty_bits,
                )
                if context.patterns
                else None
            ),
        )
