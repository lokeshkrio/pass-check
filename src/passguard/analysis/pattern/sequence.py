from passguard.context import AnalysisContext
from passguard.analysis.pattern.models import PatternFinding, PatternSeverity, PatternType


class SequenceDetector:
    def __init__(self) -> None:
        self.min_length = 3

    def analyze(self, context: AnalysisContext) -> None:
        if not context.password or len(context.password) < self.min_length:
            return

        pwd = context.password.lower()
        seq_start = 0
        seq_dir = 0  # 1 for ascending, -1 for descending

        for i in range(1, len(pwd)):
            diff = ord(pwd[i]) - ord(pwd[i - 1])

            if abs(diff) == 1 and (pwd[i].isalnum() and pwd[i - 1].isalnum()):
                if seq_dir == 0:
                    seq_dir = diff
                elif seq_dir != diff:
                    # Direction changed, evaluate the previous sequence
                    self._evaluate(context, pwd, seq_start, i)
                    seq_start = i - 1
                    seq_dir = diff
            else:
                if seq_dir != 0:
                    self._evaluate(context, pwd, seq_start, i)
                seq_start = i
                seq_dir = 0

        if seq_dir != 0:
            self._evaluate(context, pwd, seq_start, len(pwd))

    def _evaluate(self, context: AnalysisContext, pwd: str, start: int, end: int) -> None:
        length = end - start
        if length >= self.min_length:
            seq_str = context.password[start:end]
            is_digit = seq_str.isdigit()

            severity = PatternSeverity.LOW
            if length >= 5:
                severity = PatternSeverity.HIGH
            elif length == 4:
                severity = PatternSeverity.MEDIUM

            context.patterns.append(
                PatternFinding(
                    type=PatternType.SEQUENTIAL_DIGITS if is_digit else PatternType.SEQUENTIAL_LETTERS,
                    severity=severity,
                    start=start,
                    end=end,
                    description=f"Sequential characters '{seq_str}' found."
                )
            )
