import pytest
from passguard.analyzer import PasswordAnalyzer
from passguard.analysis.dictionary.provider import SetDictionaryProvider
from passguard.analysis.cracktime.models import AttackProfile


def test_keyboard_walk_and_sequence():
    analyzer = PasswordAnalyzer()
    report = analyzer.analyze("qwerty12345")
    
    assert report.patterns is not None
    findings = [p.description for p in report.patterns.findings]
    
    has_keyboard = any("Keyboard walk" in f and "qwerty" in f for f in findings)
    has_sequence = any("Sequential" in f and "12345" in f for f in findings)
    
    assert has_keyboard
    assert has_sequence


def test_dictionary_match():
    provider = SetDictionaryProvider(["password", "admin", "letmein"])
    analyzer = PasswordAnalyzer(dictionary_provider=provider)
    
    report = analyzer.analyze("my_admin_password")
    
    assert len(report.dictionary_matches) >= 2
    words = {m.word for m in report.dictionary_matches}
    assert "admin" in words
    assert "password" in words


def test_leetspeak_normalization():
    provider = SetDictionaryProvider(["password"])
    analyzer = PasswordAnalyzer(dictionary_provider=provider)
    
    # "p@ssw0rd" normalizes to "password" which matches the dictionary
    report = analyzer.analyze("p@ssw0rd")
    
    assert len(report.dictionary_matches) > 0
    assert report.dictionary_matches[0].word == "password"


def test_crack_time_estimation():
    profiles = [AttackProfile("Custom RTX", 10_000_000)]
    analyzer = PasswordAnalyzer(attack_profiles=profiles)
    
    report = analyzer.analyze("correcthorsebatterystaple")
    
    assert "Custom RTX" in report.crack_times
    assert report.crack_times["Custom RTX"] > 0


def test_recommendation_engine():
    analyzer = PasswordAnalyzer()
    report = analyzer.analyze("11111111")
    
    assert report.recommendations
    messages = [r.message for r in report.recommendations]
    
    # Should flag repeated characters
    assert any("repeated characters" in m.lower() for m in messages)
