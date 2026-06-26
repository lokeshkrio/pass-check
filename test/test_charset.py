from passguard.analysis.charset import CharacterAnalyzer
from passguard.context import AnalysisContext


def test_character_analysis():
    analyzer = CharacterAnalyzer()

    # Case 1: Mixed password
    context = AnalysisContext(password="Abc123@!")
    analyzer.analyze(context)
    result = context.require_characters()
    assert result.length == 8
    assert result.uppercase == 1
    assert result.lowercase == 2
    assert result.digits == 3
    assert result.symbols == 2

    # Case 2: Empty password
    context = AnalysisContext(password="")
    analyzer.analyze(context)
    result = context.require_characters()
    assert result.length == 0
    assert result.uppercase == 0
    assert result.lowercase == 0
    assert result.digits == 0
    assert result.symbols == 0

    # Case 3: Lowercase only
    context = AnalysisContext(password="abc")
    analyzer.analyze(context)
    result = context.require_characters()
    assert result.length == 3
    assert result.uppercase == 0
    assert result.lowercase == 3
    assert result.digits == 0
    assert result.symbols == 0

    # Case 4: Digits only
    context = AnalysisContext(password="123")
    analyzer.analyze(context)
    result = context.require_characters()
    assert result.length == 3
    assert result.uppercase == 0
    assert result.lowercase == 0
    assert result.digits == 3
    assert result.symbols == 0

    # Case 5: Special characters
    context = AnalysisContext(password="p@$$w0rd")
    analyzer.analyze(context)
    result = context.require_characters()
    assert result.length == 8
    assert result.uppercase == 0
    assert result.lowercase == 4
    assert result.digits == 1
    assert result.symbols == 3

    # Case 6: Unicode
    context = AnalysisContext(password="😁😁😁")
    analyzer.analyze(context)
    result = context.require_characters()
    assert result.length == 3
    assert result.unicode == 3
