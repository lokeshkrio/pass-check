from passguard.analysis.charset import CharacterAnalyzer
from passguard.analysis.effective_entropy import EffectiveEntropyAnalyzer
from passguard.analysis.entropy import EntropyAnalyzer
from passguard.analysis.pattern.engine import PatternAnalyzer
from passguard.analysis.pattern.models import PatternResult
from passguard.analysis.scoring import ScoreAnalyzer
from passguard.analysis.dictionary import DictionaryAnalyzer, DictionaryProvider
from passguard.analysis.mutations import LeetspeakNormalizer
from passguard.analysis.cracktime import CrackTimeAnalyzer, AttackProfile
from passguard.analysis.recommendations import RecommendationEngine
from passguard.context import AnalysisContext
from passguard.exceptions import InvalidPasswordError
from passguard.models import PasswordReport


class PasswordAnalyzer:

    def __init__(
        self,
        dictionary_provider: DictionaryProvider | None = None,
        attack_profiles: list[AttackProfile] | None = None,
    ) -> None:
        self.character = CharacterAnalyzer()
        self.entropy = EntropyAnalyzer()
        self.pattern = PatternAnalyzer()
        self.leetspeak = LeetspeakNormalizer()
        self.dictionary = DictionaryAnalyzer(provider=dictionary_provider)
        self.effective_entropy = EffectiveEntropyAnalyzer()
        self.score = ScoreAnalyzer()
        self.cracktime = CrackTimeAnalyzer(profiles=attack_profiles)
        self.recommendations = RecommendationEngine()

    def analyze(self, password: str) -> PasswordReport:

        if not isinstance(password, str):
            raise InvalidPasswordError("Password must be a string.")

        context = AnalysisContext(password=password)

        # 1. Character & Entropy
        self.character.analyze(context)
        self.entropy.analyze(context)

        # 2. Structural Patterns
        self.pattern.analyze(context)

        # 3. Mutations & Dictionary
        self.leetspeak.analyze(context)
        self.dictionary.analyze(context)

        # 4. Final Entropy & Score
        self.effective_entropy.analyze(context)
        self.score.analyze(context)

        # 5. Advanced Estimation & Reporting
        self.cracktime.analyze(context)
        self.recommendations.analyze(context)

        score = context.require_score()

        return PasswordReport(
            score=score.score,
            strength=score.strength.value,
            characters=context.require_characters(),
            entropy=context.require_entropy(),
            recommendations=context.recommendations,
            dictionary_matches=context.dictionary_matches,
            crack_times=context.crack_times,
            patterns=(
                PatternResult(
                    findings=context.patterns,
                    penalty=context.pattern_penalty_bits,
                )
                if context.patterns
                else None
            ),
        )
