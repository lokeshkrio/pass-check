from passguard.constants import (
    DIGITS,
    LOWERCASE,
    SYMBOLS,
    UPPERCASE,
    WHITESPACE,
)
from passguard.context import AnalysisContext
from passguard.models import CharacterAnalysis


class CharacterAnalyzer:
    def analyze(self, context: AnalysisContext) -> None:

        password = context.password

        lowercase = 0
        uppercase = 0
        digits = 0
        symbols = 0
        whitespace = 0
        unicode_chars = 0

        for ch in password:
            if ch in LOWERCASE:
                lowercase += 1

            elif ch in UPPERCASE:
                uppercase += 1

            elif ch in DIGITS:
                digits += 1

            elif ch in SYMBOLS:
                symbols += 1

            elif ch in WHITESPACE:
                whitespace += 1

            else:
                unicode_chars += 1

        context.characters = CharacterAnalysis(
            length=len(password),
            lowercase=lowercase,
            uppercase=uppercase,
            digits=digits,
            symbols=symbols,
            whitespace=whitespace,
            unicode=unicode_chars,
        )
