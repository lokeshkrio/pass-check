from passguard.analysis.pattern.models import (
    PatternFinding,
    PatternSeverity,
    PatternType,
)
from passguard.context import AnalysisContext


class RepeatedCharacterDetector:
    def analyze(self, context: AnalysisContext) -> None:
        password = context.password

        if not password:
            return

        current_char = password[0]
        start_index = 0
        length = 1

        for i in range(1, len(password)):
            if password[i] == current_char:
                length += 1
            else:
                self._evaluate_sequence(context, current_char, start_index, i, length)

                # Reset for the new character
                current_char = password[i]
                start_index = i
                length = 1

        # Evaluate the final sequence at the end of the string
        self._evaluate_sequence(
            context, current_char, start_index, len(password), length
        )

    def _evaluate_sequence(
        self,
        context: AnalysisContext,
        char: str,
        start_index: int,
        end_index: int,
        length: int,
    ) -> None:

        if length > 2:
            if length == 3:
                severity = PatternSeverity.LOW
            elif length == 4:
                severity = PatternSeverity.MEDIUM
            else:
                severity = PatternSeverity.HIGH

            finding = PatternFinding(
                type=PatternType.REPEATED_CHARACTER,
                severity=severity,
                start=start_index,
                end=end_index,
                description=(f"Repeated character '{char}' found {length} times."),
            )

            context.patterns.append(finding)


class RepeatedSubstringDetector:
    """Detect consecutive repeated multi-character substrings."""

    _MIN_UNIT_LENGTH = 2
    _MIN_REPEAT_COUNT = 2

    def analyze(self, context: AnalysisContext) -> None:
        password = context.password
        index = 0

        while index < len(password):
            match = self._find_best_match(password, index)

            if match is None:
                index += 1
                continue

            unit, repeat_count, end_index = match
            context.patterns.append(
                PatternFinding(
                    type=PatternType.REPEATED_SUBSTRING,
                    severity=self._severity_for(repeat_count),
                    start=index,
                    end=end_index,
                    description=(
                        f"Repeated substring '{unit}' found {repeat_count} times."
                    ),
                )
            )
            index = end_index

    def _find_best_match(
        self,
        password: str,
        start_index: int,
    ) -> tuple[str, int, int] | None:
        remaining_length = len(password) - start_index
        max_unit_length = remaining_length // self._MIN_REPEAT_COUNT
        best_match: tuple[str, int, int] | None = None

        for unit_length in range(self._MIN_UNIT_LENGTH, max_unit_length + 1):
            unit = password[start_index : start_index + unit_length]

            if len(set(unit)) == 1:
                continue

            repeat_count = self._count_repeats(password, start_index, unit)

            if repeat_count < self._MIN_REPEAT_COUNT:
                continue

            end_index = start_index + (unit_length * repeat_count)
            candidate = (unit, repeat_count, end_index)

            if self._is_better_match(candidate, best_match):
                best_match = candidate

        return best_match

    def _count_repeats(self, password: str, start_index: int, unit: str) -> int:
        repeat_count = 0
        unit_length = len(unit)
        index = start_index

        while password[index : index + unit_length] == unit:
            repeat_count += 1
            index += unit_length

        return repeat_count

    def _is_better_match(
        self,
        candidate: tuple[str, int, int],
        current: tuple[str, int, int] | None,
    ) -> bool:
        if current is None:
            return True

        candidate_unit, candidate_repeats, candidate_end = candidate
        current_unit, current_repeats, current_end = current

        candidate_span = candidate_end
        current_span = current_end

        if candidate_repeats != current_repeats:
            return candidate_repeats > current_repeats

        if candidate_span != current_span:
            return candidate_span > current_span

        return len(candidate_unit) < len(current_unit)

    def _severity_for(self, repeat_count: int) -> PatternSeverity:
        if repeat_count == 2:
            return PatternSeverity.LOW

        if repeat_count == 3:
            return PatternSeverity.MEDIUM

        return PatternSeverity.HIGH
