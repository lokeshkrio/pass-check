from passguard.context import AnalysisContext
from passguard.analysis.pattern.models import PatternFinding, PatternSeverity, PatternType


# Adjacency map for standard QWERTY keyboard
QWERTY_MAP = {
    '1': '2q',
    '2': '13qw',
    '3': '24we',
    '4': '35er',
    '5': '46rt',
    '6': '57ty',
    '7': '68yu',
    '8': '79ui',
    '9': '80io',
    '0': '9-op',
    '-': '0=p[',
    '=': '-[',
    'q': '12wa',
    'w': '23qeas',
    'e': '34wrsd',
    'r': '45etdf',
    't': '56ryfg',
    'y': '67tugh',
    'u': '78yihj',
    'i': '89uojk',
    'o': '90ipkl',
    'p': '0-o[l;',
    '[': '-=p\';',
    ']': '=\\',
    'a': 'qwsz',
    's': 'weadxz',
    'd': 'ersfxc',
    'f': 'rtdgcv',
    'g': 'tyfhvb',
    'h': 'yugjbn',
    'j': 'uihknm',
    'k': 'iojl',
    'l': 'opk;',
    ';': 'p[l\'',
    '\'': '[;',
    'z': 'asx',
    'x': 'sdzc',
    'c': 'dfxv',
    'v': 'fgcb',
    'b': 'ghvn',
    'n': 'hjbm',
    'm': 'jkn',
}

class KeyboardWalkDetector:
    def __init__(self) -> None:
        self.min_length = 3

    def analyze(self, context: AnalysisContext) -> None:
        if not context.password or len(context.password) < self.min_length:
            return

        pwd = context.password.lower()
        walk_start = 0

        for i in range(1, len(pwd)):
            prev = pwd[i - 1]
            curr = pwd[i]

            # Check if they are adjacent
            if prev in QWERTY_MAP and curr in QWERTY_MAP[prev]:
                continue
            else:
                self._evaluate(context, pwd, walk_start, i)
                walk_start = i

        self._evaluate(context, pwd, walk_start, len(pwd))

    def _evaluate(self, context: AnalysisContext, pwd: str, start: int, end: int) -> None:
        length = end - start
        if length >= self.min_length:
            walk_str = context.password[start:end]

            severity = PatternSeverity.LOW
            if length >= 5:
                severity = PatternSeverity.HIGH
            elif length == 4:
                severity = PatternSeverity.MEDIUM

            context.patterns.append(
                PatternFinding(
                    type=PatternType.KEYBOARD_WALK,
                    severity=severity,
                    start=start,
                    end=end,
                    description=f"Keyboard walk pattern '{walk_str}' found."
                )
            )
