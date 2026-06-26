# PassGuard

PassGuard is an experimental password analysis library written in Python.

The goal is to build a modular password strength engine from first principles,
without wrapping existing estimators such as zxcvbn. The project is intended to
show the engineering and security reasoning behind each analyzer: character
classification, entropy estimation, pattern detection, effective entropy,
scoring, and eventually recommendations.

PassGuard is still early-stage. It is useful as a learning and portfolio
project, but it is not yet a complete production password policy system.

## Features

Currently implemented:

- Character analysis
- Theoretical entropy estimation
- Repeated character detection
- Repeated substring detection
- Sequential pattern detection (e.g. 12345, abcde)
- Keyboard walk detection (e.g. qwerty, asdf)
- Dictionary matching (pluggable providers for custom lists)
- Leetspeak normalization for dictionary matches
- Pattern-adjusted effective entropy
- Crack time estimation via configurable attack profiles
- Entropy-based password scoring
- Actionable recommendation engine
- Structured report models using dataclasses
- Strict type checking with mypy
- Tests with pytest

Planned:

- Password policy validation
- Exportable reports
- Breach detection through Have I Been Pwned

## Pipeline Flow

```text
Password
    │
    ▼
Character Analyzer
    │
    ▼
Entropy Analyzer
    │
    ▼
Pattern Analyzer
    │
    ▼
Dictionary Analyzer
    │
    ▼
Effective Entropy
    │
    ▼
Scoring
    │
    ▼
Recommendations
```

## Requirements

- Python 3.13+
- uv

Development tools are managed through `pyproject.toml`:

- pytest
- ruff
- mypy
- hatchling

## Installation

For local development:

```bash
uv sync
```

Run tests:

```bash
uv run pytest
```

Run linting:

```bash
uv run ruff check .
```

Run type checking:

```bash
uv run mypy src
```

## Usage

```python
from passguard import PasswordAnalyzer

analyzer = PasswordAnalyzer()
report = analyzer.analyze("abcabcabc")

print(report.score)
print(report.strength)
print(report.entropy.theoretical_bits)
print(report.entropy.effective_bits)
```

The analyzer returns a `PasswordReport` containing:

- `score`: numeric score from 0 to 100
- `strength`: human-readable strength label
- `characters`: character composition result
- `entropy`: theoretical and effective entropy
- `patterns`: detected weakness patterns, when present
- `recommendations`: reserved for the future recommendation engine

## Core Idea

Simple entropy formulas can overestimate weak passwords.

For example, `abcabcabc` is nine lowercase characters. A naive entropy formula
treats it as if all nine characters were independently selected. PassGuard
detects that the password is really a repeated substring and lowers its
effective entropy.

This separation matters:

- `theoretical_bits`: what the password would have if each character were
  independently chosen from the detected character pool
- `effective_bits`: adjusted entropy after known weak patterns are considered

## Project Structure

```text
src/passguard/
    analyzer.py              # Orchestrates the analysis pipeline
    context.py               # Shared mutable analysis context
    models.py                # Public dataclass result models
    constants.py             # Character pools and constants
    exceptions.py            # Library exceptions

    analysis/
        charset.py           # Character composition
        entropy.py           # Theoretical entropy
        effective_entropy.py # Pattern-adjusted entropy
        scoring.py           # Score and strength label
        mutations.py         # Leetspeak normalization
        recommendations.py   # Actionable feedback engine

        pattern/
            engine.py        # Pattern detector orchestration
            models.py        # Pattern result models
            repeated.py      # Repeated character and substring detection
            sequence.py      # Sequential character detection
            keyboard.py      # Spatial keyboard walk detection
        
        dictionary/
            analyzer.py      # Dictionary matching
            models.py        # Dictionary match results
            provider.py      # Pluggable wordlist providers
            
        cracktime/
            analyzer.py      # Time-to-crack estimation
            models.py        # Attack profiles
```

## Documentation

- [Detailed Manual](docs.md)
- [Architecture](ARCHITECTURE.md)
- [Roadmap](ROADMAP.md)

## Design Principles

- Build the algorithms directly instead of wrapping an existing estimator
- Keep analyzers small and independently testable
- Use composition over inheritance
- Store analysis state in `AnalysisContext`
- Use dataclasses for public result models
- Keep the public API simple
- Prefer clear, explainable algorithms over clever shortcuts

## License

MIT
