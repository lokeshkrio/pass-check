from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AttackProfile:
    name: str
    guesses_per_second: int


ONLINE_THROTTLED = AttackProfile("Online throttled", 10)
ONLINE_UNTHROTTLED = AttackProfile("Online unthrottled", 1_000)
OFFLINE_SLOW_HASH = AttackProfile("Offline slow hash", 10_000)
OFFLINE_FAST_HASH = AttackProfile("Offline fast hash", 10_000_000_000)

DEFAULT_PROFILES = [
    ONLINE_THROTTLED,
    ONLINE_UNTHROTTLED,
    OFFLINE_SLOW_HASH,
    OFFLINE_FAST_HASH,
]
