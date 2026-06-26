from passguard.analysis.charset import CharacterAnalyzer
from passguard.analysis.effective_entropy import EffectiveEntropyAnalyzer
from passguard.analysis.entropy import EntropyAnalyzer
from passguard.analysis.pattern.engine import PatternAnalyzer
from passguard.analyzer import PasswordAnalyzer
from passguard.context import AnalysisContext


def test_effective_entropy_matches_theoretical_entropy_without_patterns() -> None:
    context = AnalysisContext(password="secure")

    CharacterAnalyzer().analyze(context)
    EntropyAnalyzer().analyze(context)
    PatternAnalyzer().analyze(context)
    EffectiveEntropyAnalyzer().analyze(context)

    entropy = context.require_entropy()
    assert entropy.effective_bits == entropy.theoretical_bits
    assert context.pattern_penalty_bits == 0.0


def test_repeated_substring_reduces_effective_entropy() -> None:
    context = AnalysisContext(password="abcabcabc")

    CharacterAnalyzer().analyze(context)
    EntropyAnalyzer().analyze(context)
    PatternAnalyzer().analyze(context)
    EffectiveEntropyAnalyzer().analyze(context)

    entropy = context.require_entropy()
    assert entropy.theoretical_bits == 42.3
    assert entropy.effective_bits == 15.68
    assert context.pattern_penalty_bits == 26.62


def test_repeated_character_reduces_effective_entropy() -> None:
    context = AnalysisContext(password="aaaa")

    CharacterAnalyzer().analyze(context)
    EntropyAnalyzer().analyze(context)
    PatternAnalyzer().analyze(context)
    EffectiveEntropyAnalyzer().analyze(context)

    entropy = context.require_entropy()
    assert entropy.theoretical_bits == 18.8
    assert entropy.effective_bits == 6.7
    assert context.pattern_penalty_bits == 12.1


def test_password_report_exposes_pattern_penalty() -> None:
    report = PasswordAnalyzer().analyze("abcabcabc")

    assert report.patterns is not None
    assert report.patterns.penalty == 26.62
    assert report.entropy.effective_bits < report.entropy.theoretical_bits
