from passguard.context import AnalysisContext
from passguard.analysis.cracktime.models import AttackProfile, DEFAULT_PROFILES


class CrackTimeAnalyzer:
    def __init__(self, profiles: list[AttackProfile] | None = None) -> None:
        self.profiles = profiles if profiles is not None else DEFAULT_PROFILES

    def analyze(self, context: AnalysisContext) -> None:
        entropy = context.require_entropy()
        effective_bits = entropy.effective_bits

        # Number of possible combinations is 2^effective_bits
        # To find expected crack time, we divide by 2 for average time (optional, but standard),
        # or we just calculate total time to exhaust space.
        # Usually, time = (2^bits / 2) / speed
        combinations = 2**effective_bits
        expected_guesses = combinations / 2

        for profile in self.profiles:
            if profile.guesses_per_second > 0:
                seconds = expected_guesses / profile.guesses_per_second
                context.crack_times[profile.name] = seconds
            else:
                context.crack_times[profile.name] = float("inf")
