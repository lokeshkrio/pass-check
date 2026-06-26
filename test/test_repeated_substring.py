import pytest

from passguard.analysis.pattern.models import PatternSeverity, PatternType
from passguard.analysis.pattern.repeated import RepeatedSubstringDetector
from passguard.context import AnalysisContext


@pytest.fixture
def detector() -> RepeatedSubstringDetector:
    return RepeatedSubstringDetector()


def test_no_repeated_substring(detector: RepeatedSubstringDetector) -> None:
    context = AnalysisContext(password="password123")

    detector.analyze(context)

    assert context.patterns == []


def test_detects_repeated_substring(detector: RepeatedSubstringDetector) -> None:
    context = AnalysisContext(password="abcabc")

    detector.analyze(context)

    assert len(context.patterns) == 1

    finding = context.patterns[0]
    assert finding.type == PatternType.REPEATED_SUBSTRING
    assert finding.severity == PatternSeverity.LOW
    assert finding.start == 0
    assert finding.end == 6


def test_detects_repeated_substring_inside_password(
    detector: RepeatedSubstringDetector,
) -> None:
    context = AnalysisContext(password="xx20242024yy")

    detector.analyze(context)

    assert len(context.patterns) == 1

    finding = context.patterns[0]
    assert finding.start == 2
    assert finding.end == 10


def test_repeated_substring_severity_increases_with_repeats(
    detector: RepeatedSubstringDetector,
) -> None:
    context = AnalysisContext(password="abcabcabc")

    detector.analyze(context)

    assert len(context.patterns) == 1
    assert context.patterns[0].severity == PatternSeverity.MEDIUM


def test_single_character_repeats_are_ignored(
    detector: RepeatedSubstringDetector,
) -> None:
    context = AnalysisContext(password="aaaa")

    detector.analyze(context)

    assert context.patterns == []


def test_multiple_non_overlapping_substrings(
    detector: RepeatedSubstringDetector,
) -> None:
    context = AnalysisContext(password="ababxxcdcd")

    detector.analyze(context)

    assert len(context.patterns) == 2
    assert context.patterns[0].start == 0
    assert context.patterns[0].end == 4
    assert context.patterns[1].start == 6
    assert context.patterns[1].end == 10
