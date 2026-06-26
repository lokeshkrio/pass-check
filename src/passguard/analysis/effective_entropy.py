import math

from passguard.analysis.pattern.models import PatternFinding, PatternType
from passguard.context import AnalysisContext
from passguard.models import EntropyResult


class EffectiveEntropyAnalyzer:
    """Apply pattern-based reductions to theoretical entropy."""

    def analyze(self, context: AnalysisContext) -> None:
        entropy = context.require_entropy()

        if entropy.charset_size == 0 or not context.patterns:
            return

        bits_per_character = math.log2(entropy.charset_size)
        penalty = 0.0

        for finding in context.patterns:
            penalty += self._penalty_for_finding(
                password=context.password,
                finding=finding,
                bits_per_character=bits_per_character,
            )

        context.pattern_penalty_bits = round(penalty, 2)
        context.entropy = EntropyResult(
            theoretical_bits=entropy.theoretical_bits,
            effective_bits=round(max(entropy.theoretical_bits - penalty, 0.0), 2),
            charset_size=entropy.charset_size,
        )

    def _penalty_for_finding(
        self,
        password: str,
        finding: PatternFinding,
        bits_per_character: float,
    ) -> float:
        span = password[finding.start : finding.end]

        if not span:
            return 0.0

        match finding.type:
            case PatternType.REPEATED_CHARACTER:
                estimated_bits = self._repeated_character_bits(
                    span=span,
                    bits_per_character=bits_per_character,
                )
            case PatternType.REPEATED_SUBSTRING:
                estimated_bits = self._repeated_substring_bits(
                    span=span,
                    bits_per_character=bits_per_character,
                )
            case _:
                return 0.0

        independent_bits = len(span) * bits_per_character
        return max(independent_bits - estimated_bits, 0.0)

    def _repeated_character_bits(
        self,
        span: str,
        bits_per_character: float,
    ) -> float:
        return bits_per_character + math.log2(len(span))

    def _repeated_substring_bits(
        self,
        span: str,
        bits_per_character: float,
    ) -> float:
        unit = self._smallest_repeating_unit(span)

        if unit is None:
            return len(span) * bits_per_character

        repeat_count = len(span) // len(unit)
        return (len(unit) * bits_per_character) + math.log2(repeat_count)

    def _smallest_repeating_unit(self, span: str) -> str | None:
        for unit_length in range(1, (len(span) // 2) + 1):
            if len(span) % unit_length != 0:
                continue

            unit = span[:unit_length]

            if unit * (len(span) // unit_length) == span:
                return unit

        return None
