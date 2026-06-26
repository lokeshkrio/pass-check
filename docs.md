# PassGuard Password Analysis Engine Documentation

Welcome to the **PassGuard** developer and user manual. PassGuard is a modular, first-principles password intelligence and strength analysis library for Python. 

Unlike traditional libraries that wrap external estimators (like `zxcvbn`), PassGuard executes a clean, extensible, multi-stage pipeline. It breaks down passwords by character composition, theoretical entropy, structural patterns (repetition, sequences, keyboard paths), dictionary matches, and mutations, ultimately deriving an adjusted *effective entropy*, a realistic score, crack-time estimates, and actionable user feedback.

---

## 1. Architectural Philosophy & Core Mechanics

PassGuard is designed around three main principles:
1. **Unwrapped First-Principles Estimation:** The algorithms are built directly into the library rather than calling external executables or complex opaque heuristics.
2. **Pipelines and Mutating Context:** The analysis executes as a sequence of distinct analyzers. State is shared via a single, mutable [AnalysisContext](file:///d:/LK/py/PassGuard/src/passguard/context.py) object, ensuring that state transitions are explicit and analyzers remain decoupled.
3. **Theoretical vs. Effective Entropy:** Real-world passwords rarely follow random character selection. PassGuard separates what a password *could* be (theoretical entropy based on character sets) from what it *actually* is when accounting for human-generated patterns (effective entropy).

```
               [ Input Password String ]
                           │
                           ▼
                  AnalysisContext (State)
                           │
 ┌─────────────────────────┴─────────────────────────┐
 │ 1. Character & Entropy Analysis                   │
 │    ├─ CharacterAnalyzer                           │
 │    └─ EntropyAnalyzer                             │
 ├───────────────────────────────────────────────────┤
 │ 2. Structural Pattern Recognition                 │
 │    ├─ RepeatedCharacterDetector                   │
 │    ├─ RepeatedSubstringDetector                   │
 │    ├─ SequenceDetector (Ascending/Descending)     │
 │    └─ KeyboardWalkDetector (QWERTY Spatial Paths) │
 ├───────────────────────────────────────────────────┤
 │ 3. Mutation Normalization & Dictionary Matching   │
 │    ├─ LeetspeakNormalizer                         │
 │    └─ DictionaryAnalyzer (Pluggable Providers)    │
 ├───────────────────────────────────────────────────┤
 │ 4. Final Entropy & Score Calculations             │
 │    ├─ EffectiveEntropyAnalyzer (Penalty Math)     │
 │    └─ ScoreAnalyzer (Tiers and Scaling)           │
 ├───────────────────────────────────────────────────┤
 │ 5. Advanced Estimations & Reporting               │
 │    ├─ CrackTimeAnalyzer (Attack Profiles)         │
 │    └─ RecommendationEngine (User Feedback)        │
 └─────────────────────────┬─────────────────────────┘
                           │
                           ▼
                 [ PasswordReport Output ]
```

---

## 2. Pipeline Analyzers & Algorithms

Below is a detailed breakdown of the execution pipeline of [PasswordAnalyzer](file:///d:/LK/py/PassGuard/src/passguard/analyzer.py):

### 2.1 Character Analysis (`CharacterAnalyzer`)
Located in [charset.py](file:///d:/LK/py/PassGuard/src/passguard/analysis/charset.py), this step inspects every character in the password and groups them into character classes:
* **Lowercase:** `a-z`
* **Uppercase:** `A-Z`
* **Digits:** `0-9`
* **Symbols:** Space, punctuation, and other standard special symbols.
* **Whitespace:** Spaces, tabs, and newlines.
* **Unicode:** Non-ASCII or multi-byte characters.

### 2.2 Theoretical Entropy Calculation (`EntropyAnalyzer`)
Located in [entropy.py](file:///d:/LK/py/PassGuard/src/passguard/analysis/entropy.py), this estimates the theoretical entropy under the assumption of random, independent character selection.
* **Pool Size ($H_{charset}$):** Summed based on detected classes:
  * Lowercase: $+26$
  * Uppercase: $+26$
  * Digits: $+10$
  * Symbols: $+32$
  * Unicode: $+256$ (Estimated unicode pool size)
* **Entropy Formula:**
  $$\text{theoretical\_bits} = L \times \log_2(H_{charset})$$
  *(where $L$ is the length of the password)*

### 2.3 Structural Pattern Recognition (`PatternAnalyzer`)
Located in the [pattern](file:///d:/LK/py/PassGuard/src/passguard/analysis/pattern/) directory, this coordinator runs four specialized detectors that append findings to `context.patterns`:
1. **Repeated Character Detector:** Identifies contiguous blocks of the same character (e.g., `aaaa`). Runs of length 1 or 2 are ignored to avoid flagging common dictionary words (e.g., `look`).
2. **Repeated Substring Detector:** Identifies contiguous repeats of multi-character blocks (e.g., `abcabc` has a unit size of 3 and repeats 2 times). It searches for the smallest repeating unit dynamically.
3. **Sequence Detector:** Scans for alphabetic or numeric runs that increment or decrement by a step of $1$ ASCII/Unicode value (e.g., `12345`, `fedc`). Minimum matching length is 3.
4. **Keyboard Walk Detector:** Matches contiguous characters following standard spatial key adjacencies on a QWERTY keyboard map (e.g., `qwerty`, `asdfg`, `zxcv`).

### 2.4 Mutation & Normalization (`LeetspeakNormalizer`)
Located in [mutations.py](file:///d:/LK/py/PassGuard/src/passguard/analysis/mutations.py), this component maps common leetspeak substitutions (e.g., `@` $\rightarrow$ `a`, `0` $\rightarrow$ `o`, `$` $\rightarrow$ `s`, `1` $\rightarrow$ `i`/`l`) to a standardized form. If mutations are found, it generates a list of candidate plaintexts and appends them to `context.normalized_passwords` for dictionary scanning.

### 2.5 Dictionary Matching (`DictionaryAnalyzer`)
Located in the [dictionary](file:///d:/LK/py/PassGuard/src/passguard/analysis/dictionary/) directory, this scans both the original password and mutated candidates against a dictionary list.
* It checks for both **exact matches** and **substring matches** (for substrings of length $\ge 3$).
* **Complexity**: It runs in $O(L^2)$ time complexity relative to the password length $L$ to slice substring candidates, performing an $O(1)$ set lookup check against the loaded dictionary wordlist.
* It uses a pluggable [DictionaryProvider](file:///d:/LK/py/PassGuard/src/passguard/analysis/dictionary/provider.py) architecture, allowing set-based, file-based, or built-in dictionary checks (which default to a built-in top 1000 common passwords file).

### 2.6 Effective Entropy Calculation (`EffectiveEntropyAnalyzer`)
Located in [effective_entropy.py](file:///d:/LK/py/PassGuard/src/passguard/analysis/effective_entropy.py), this modifies the entropy bits based on structural pattern findings. To prevent double-penalizing overlapping patterns (e.g. when sequence `abc` overlaps with repeated substring `abcabcabc`), it sorts patterns by span length descending and tracks covered indices. It computes:
* **Repeated Character Pattern Cost:**
  $$\text{estimated\_bits} = \log_2(H_{charset}) + \log_2(\text{run\_length})$$
* **Repeated Substring Pattern Cost:**
  $$\text{estimated\_bits} = (\text{unit\_length} \times \log_2(H_{charset})) + \log_2(\text{repeat\_count})$$
* **Keyboard Walk Pattern Cost:**
  $$\text{estimated\_bits} = \log_2(H_{charset}) + (\text{walk\_length} - 1) \times 1.5$$
* **Sequential Run Pattern Cost:**
  $$\text{estimated\_bits} = \log_2(H_{charset}) + 1.0$$
* **Penalty:**
  $$\text{penalty} = \text{independent\_bits} - \text{estimated\_bits}$$
  $$\text{effective\_bits} = \max(\text{theoretical\_bits} - \sum \text{penalties}, 0.0)$$

### 2.7 Score and Strength Tiering (`ScoreAnalyzer`)
Located in [scoring.py](file:///d:/LK/py/PassGuard/src/passguard/analysis/scoring.py), this converts the final `effective_bits` value into a standardized scale:
* **Score:** Scaled linearly up to a full score threshold of $80$ bits:
  $$\text{score} = \min\left(\left\lfloor \frac{\text{effective\_bits}}{80} \times 100 \right\rfloor, 100\right)$$
* **Strength Thresholds:**
  * **Very Weak:** $< 20$ bits of effective entropy
  * **Weak:** $< 40$ bits of effective entropy
  * **Moderate:** $< 60$ bits of effective entropy
  * **Strong:** $< 80$ bits of effective entropy
  * **Very Strong:** $\ge 80$ bits of effective entropy

### 2.8 Crack Time Estimation (`CrackTimeAnalyzer`)
Located in the [cracktime](file:///d:/LK/py/PassGuard/src/passguard/analysis/cracktime/) directory, this estimates the time required to guess the password under different attacker speeds.
* **Formula:**
  $$\text{expected\_guesses} = \frac{2^{\text{effective\_bits}}}{2}$$
  $$\text{seconds\_to\_crack} = \frac{\text{expected\_guesses}}{\text{guesses\_per\_second}}$$

### 2.9 Recommendation Engine (`RecommendationEngine`)
Located in [recommendations.py](file:///d:/LK/py/PassGuard/src/passguard/analysis/recommendations.py), this engine analyzes the combined context (short length, patterns, dictionary matches) to construct clear, actionable, deduplicated recommendations for end users.

---

## 3. Public API & Return Types

All core models returned by the library are strictly typed [dataclasses](https://docs.python.org/3/library/dataclasses.html). They are defined in [models.py](file:///d:/LK/py/PassGuard/src/passguard/models.py) and their submodules.

### 3.1 Class: `PasswordAnalyzer`
The primary entrypoint.
```python
class PasswordAnalyzer:
    def __init__(
        self,
        dictionary_provider: DictionaryProvider | None = None,
        attack_profiles: list[AttackProfile] | None = None,
    ) -> None:
        ...

    def analyze(self, password: str) -> PasswordReport:
        ...
```
* **Parameters:**
  * `dictionary_provider` (Optional): A class conforming to `DictionaryProvider`. Defaults to `BuiltinDictionaryProvider` (looks up a top 1000 list).
  * `attack_profiles` (Optional): A list of custom `AttackProfile` configuration items. Defaults to `DEFAULT_PROFILES`.
* **Raises:**
  * `InvalidPasswordError`: If the input is not a string.

---

### 3.2 Dataclass: `PasswordReport`
This is the root result class returned by `PasswordAnalyzer.analyze()`.
```python
@dataclass(slots=True, frozen=True)
class PasswordReport:
    score: int
    strength: str
    characters: CharacterAnalysis
    entropy: EntropyResult
    recommendations: list[Recommendation]
    patterns: PatternResult | None = None
    dictionary_matches: list[DictionaryMatchResult] = field(default_factory=list)
    crack_times: dict[str, float] = field(default_factory=dict)
```
* **`score`** (`int`): Password score from `0` (worst) to `100` (best).
* **`strength`** (`str`): Word description of the password strength. String representation of the `Strength` Enum: `"Very Weak"`, `"Weak"`, `"Moderate"`, `"Strong"`, or `"Very Strong"`.
* **`characters`** (`CharacterAnalysis`): Detailed character composition statistics.
* **`entropy`** (`EntropyResult`): Theoretical vs. pattern-penalized entropy metrics.
* **`recommendations`** (`list[Recommendation]`): Deduplicated list of warnings and improvement suggestions.
* **`patterns`** (`PatternResult | None`): Pattern details and aggregated pattern penalty bits (if any patterns were matched).
* **`dictionary_matches`** (`list[DictionaryMatchResult]`): Substrings or full matches detected in the dictionary list.
* **`crack_times`** (`dict[str, float]`): Map of attack profile names to the estimated number of seconds it would take to guess the password.

---

### 3.3 Dataclass: `CharacterAnalysis`
```python
@dataclass(slots=True, frozen=True)
class CharacterAnalysis:
    length: int
    lowercase: int
    uppercase: int
    digits: int
    symbols: int
    whitespace: int
    unicode: int
```

---

### 3.4 Dataclass: `EntropyResult`
```python
@dataclass(slots=True, frozen=True)
class EntropyResult:
    theoretical_bits: float
    effective_bits: float
    charset_size: int
```

---

### 3.5 Dataclass: `PatternResult`
```python
@dataclass(slots=True, frozen=True)
class PatternResult:
    findings: list[PatternFinding]
    penalty: float
```
* **`findings`** (`list[PatternFinding]`): List of individual patterns found.
* **`penalty`** (`float`): Total bits subtracted from theoretical entropy.

---

### 3.6 Dataclass: `PatternFinding`
```python
@dataclass(slots=True, frozen=True)
class PatternFinding:
    type: PatternType
    severity: PatternSeverity
    start: int
    end: int
    description: str
```
* **`type`** (`PatternType`): Enum representing the pattern class:
  * `PatternType.REPEATED_CHARACTER`
  * `PatternType.REPEATED_SUBSTRING`
  * `PatternType.SEQUENTIAL_DIGITS`
  * `PatternType.SEQUENTIAL_LETTERS`
  * `PatternType.KEYBOARD_WALK`
* **`severity`** (`PatternSeverity`): Severity enum value: `LOW`, `MEDIUM`, or `HIGH`.
* **`start`** (`int`): Inclusive start slice index in the original password.
* **`end`** (`int`): Exclusive end slice index in the original password.
* **`description`** (`str`): Detailed diagnostic message.

---

### 3.7 Dataclass: `DictionaryMatchResult`
```python
@dataclass(slots=True, frozen=True)
class DictionaryMatchResult:
    word: str
    is_exact_match: bool
    start: int
    end: int
    rank: int | None = None
```
* **`word`** (`str`): The dictionary word matched.
* **`is_exact_match`** (`bool`): True if the whole password matched, False if a substring matched.
* **`start`** (`int`): Inclusive start slice index in the password (or mutated candidate).
* **`end`** (`int`): Exclusive end slice index in the password.

---

### 3.8 Dataclass: `Recommendation`
```python
@dataclass(slots=True, frozen=True)
class Recommendation:
    severity: str
    message: str
```

---

### 3.9 Dataclass: `AttackProfile`
```python
@dataclass(frozen=True, slots=True)
class AttackProfile:
    name: str
    guesses_per_second: int
```
Default profiles available in [models.py](file:///d:/LK/py/PassGuard/src/passguard/analysis/cracktime/models.py):
* `"Online throttled"`: 10 guesses/sec (e.g. login form with basic lockout/rate-limiting)
* `"Online unthrottled"`: 1,000 guesses/sec (e.g. login form with poor rate-limiting)
* `"Offline slow hash"`: 10,000 guesses/sec (e.g. strong hash algorithms like bcrypt/scrypt)
* `"Offline fast hash"`: 10,000,000,000 guesses/sec (e.g. weak hash algorithms like MD5/SHA-1 run on custom GPU rigs)

---

## 4. Code Integration Examples

### 4.1 Basic Usage
Analyze a password and print the report summary.
```python
from passguard import PasswordAnalyzer

# Initialize analyzer with defaults
analyzer = PasswordAnalyzer()
report = analyzer.analyze("qwerty111111")

print(f"Score: {report.score}/100")
print(f"Strength: {report.strength}")
print(f"Theoretical Entropy: {report.entropy.theoretical_bits} bits")
print(f"Effective Entropy: {report.entropy.effective_bits} bits")

# Print recommendations
for rec in report.recommendations:
    print(f"[{rec.severity}] {rec.message}")
```

### 4.2 Custom Dictionary Integration
Provide custom set-based or file-based wordlists to target domain-specific or corporate-specific dictionaries.
```python
from passguard import PasswordAnalyzer
from passguard.analysis.dictionary.provider import SetDictionaryProvider, FileDictionaryProvider

# Custom list of prohibited organizational words
custom_words = {"enterprise", "acme", "admin", "corporate", "secret"}
provider = SetDictionaryProvider(custom_words)

# Or read from a file path:
# provider = FileDictionaryProvider("path/to/company_words.txt")

analyzer = PasswordAnalyzer(dictionary_provider=provider)
report = analyzer.analyze("ACME_Corp123!")

# Substring matches on "acme" will be detected!
print(f"Matched Dictionary Words: {[m.word for m in report.dictionary_matches]}")
```

### 4.3 Custom Attack Profiles
Define specific hardware speeds or target attacker models for cracking-time estimation.
```python
from passguard import PasswordAnalyzer
from passguard.analysis.cracktime.models import AttackProfile

# Estimate crack time using specialized hardware speeds
custom_profiles = [
    AttackProfile("Supercomputer Array", 500_000_000_000),
    AttackProfile("Single RTX 4090", 25_000_000_000)
]

analyzer = PasswordAnalyzer(attack_profiles=custom_profiles)
report = analyzer.analyze("MyS3cur3P@ssw0rd!")

for profile_name, seconds in report.crack_times.items():
    years = seconds / (3600 * 24 * 365)
    print(f"{profile_name}: {years:.2e} years to crack")
```

---

## 5. Development and Pipeline Extension

To extend PassGuard with a custom analyzer step:
1. Define a focused dataclass representation inside a module if new structured findings are needed.
2. Create an analyzer class defining an `analyze(self, context: AnalysisContext) -> None` method.
3. Update [AnalysisContext](file:///d:/LK/py/PassGuard/src/passguard/context.py) to declare fields for storing results of the analyzer.
4. Add the analyzer instance inside `PasswordAnalyzer.__init__` and call it at the desired position inside `PasswordAnalyzer.analyze()`.
5. Run unit tests using `pytest` to verify the pipeline flow remains correct.
