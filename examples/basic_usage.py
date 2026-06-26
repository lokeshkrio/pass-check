from passguard import PasswordAnalyzer
from passguard.analysis.dictionary.provider import SetDictionaryProvider
from passguard.analysis.cracktime.models import AttackProfile


def main() -> None:
    print("--- PassGuard Basic Usage Example ---")

    # 1. Standard analyzer usage
    analyzer = PasswordAnalyzer()

    passwords = [
        "123456",  # Sequential digits, very weak
        "qwerty123456",  # Keyboard walk + sequence, weak
        "p@ssw0rd123!",  # Common words with leetspeak mutations
        "correcthorsebatterystaple",  # Long passphrase, strong
    ]

    for pwd in passwords:
        print(f"\nAnalyzing password: '{pwd}'")
        report = analyzer.analyze(pwd)
        print(f"  Score: {report.score}/100")
        print(f"  Strength: {report.strength}")
        print(f"  Theoretical Entropy: {report.entropy.theoretical_bits} bits")
        print(f"  Effective Entropy: {report.entropy.effective_bits} bits")

        if report.patterns and report.patterns.findings:
            print("  Patterns Detected:")
            for pattern in report.patterns.findings:
                print(f"    - [{pattern.severity.value}] {pattern.description}")

        if report.dictionary_matches:
            print("  Dictionary Matches:")
            for match in report.dictionary_matches:
                match_type = "Exact" if match.is_exact_match else "Substring"
                print(
                    f"    - [{match_type}] '{match.word}' (at indexes {match.start}-{match.end})"
                )

        if report.recommendations:
            print("  Recommendations:")
            for rec in report.recommendations:
                print(f"    - [{rec.severity}] {rec.message}")

    # 2. Custom configuration usage
    print("\n\n--- Custom Configuration Example ---")

    # Inject custom dictionary provider
    custom_words = {"enterprise", "corporate", "internal"}
    custom_provider = SetDictionaryProvider(custom_words)

    # Inject custom attack profiles
    custom_profiles = [
        AttackProfile("Custom Supercomputer", 500_000_000_000),
        AttackProfile("Desktop CPU", 100_000),
    ]

    custom_analyzer = PasswordAnalyzer(
        dictionary_provider=custom_provider, attack_profiles=custom_profiles
    )

    custom_pwd = "corporate_secret_123"
    print(f"Analyzing password with custom config: '{custom_pwd}'")
    report = custom_analyzer.analyze(custom_pwd)
    print(f"  Score: {report.score}/100")
    print(f"  Strength: {report.strength}")

    print("  Dictionary Matches:")
    for match in report.dictionary_matches:
        print(f"    - '{match.word}'")

    print("  Crack Time Estimates:")
    for profile, seconds in report.crack_times.items():
        if seconds == float("inf"):
            print(f"    - {profile}: Practically infinite")
        else:
            years = seconds / (3600 * 24 * 365)
            print(f"    - {profile}: {years:.2e} years")


if __name__ == "__main__":
    main()
