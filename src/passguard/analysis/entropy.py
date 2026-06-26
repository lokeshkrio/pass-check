import math

from passguard.constants import UNICODE_ESTIMATED_POOL
from passguard.context import AnalysisContext
from passguard.models import EntropyResult


class EntropyAnalyzer:
    def analyze(self, context: AnalysisContext) -> None:

        chars = context.characters

        if chars is None:
            raise ValueError("Character analysis must run first.")

        charset = 0

        if chars.lowercase:
            charset += 26

        if chars.uppercase:
            charset += 26

        if chars.digits:
            charset += 10

        if chars.symbols:
            charset += 32

        if chars.unicode:
            charset += UNICODE_ESTIMATED_POOL

        if charset == 0:
            context.entropy = EntropyResult(
                theoretical_bits=0.0,
                effective_bits=0.0,
                charset_size=0,
            )
            return

        bits = chars.length * math.log2(charset)

        context.entropy = EntropyResult(
            theoretical_bits=round(bits, 2),
            effective_bits=round(bits, 2),
            charset_size=charset,
        )
