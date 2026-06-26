from passguard.context import AnalysisContext
from passguard.analysis.dictionary.models import DictionaryMatchResult
from passguard.analysis.dictionary.provider import (
    DictionaryProvider,
    BuiltinDictionaryProvider,
)


class DictionaryAnalyzer:
    def __init__(self, provider: DictionaryProvider | None = None) -> None:
        self._provider = (
            provider if provider is not None else BuiltinDictionaryProvider()
        )

    def analyze(self, context: AnalysisContext) -> None:
        words = self._provider.words()
        if not words:
            return

        passwords_to_check = [context.password]
        if context.normalized_passwords:
            passwords_to_check.extend(context.normalized_passwords)

        passwords_to_check = list(dict.fromkeys(passwords_to_check))  # deduplicate

        # Convert words to lowercase for case-insensitive matching
        words_lower = {w.lower() for w in words}

        # Check full matches and substring matches
        for pwd in passwords_to_check:
            pwd_lower = pwd.lower()

            # Substring matching (O(N^2) over the length of the password, which is usually small)
            length = len(pwd_lower)
            for i in range(length):
                for j in range(
                    i + 3, length + 1
                ):  # only check substrings of length >= 3
                    substr = pwd_lower[i:j]
                    if substr in words_lower:
                        is_exact = len(substr) == len(context.password)
                        # Check if we already have this match to avoid duplicates from normalized versions
                        match = DictionaryMatchResult(
                            word=substr, is_exact_match=is_exact, start=i, end=j
                        )
                        if match not in context.dictionary_matches:
                            context.dictionary_matches.append(match)
