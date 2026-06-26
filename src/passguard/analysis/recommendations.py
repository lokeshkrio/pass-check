from passguard.context import AnalysisContext
from passguard.models import Recommendation

class RecommendationEngine:
    def analyze(self, context: AnalysisContext) -> None:
        if not context.password:
            return

        # Check for length
        if len(context.password) < 8:
            context.recommendations.append(
                Recommendation(
                    severity="High",
                    message="Password is too short. Use at least 8 characters, preferably 12 or more."
                )
            )

        # Check for patterns
        for pattern in context.patterns:
            desc = pattern.description.lower()
            if "repeated character" in desc:
                context.recommendations.append(
                    Recommendation(
                        severity=pattern.severity.value,
                        message=f"Avoid using repeated characters ({context.password[pattern.start:pattern.end]})."
                    )
                )
            elif "keyboard walk" in desc:
                context.recommendations.append(
                    Recommendation(
                        severity=pattern.severity.value,
                        message=f"Avoid using sequential keyboard paths ({context.password[pattern.start:pattern.end]})."
                    )
                )
            elif "sequential" in desc:
                context.recommendations.append(
                    Recommendation(
                        severity=pattern.severity.value,
                        message=f"Avoid using sequences like '{context.password[pattern.start:pattern.end]}'."
                    )
                )
            elif "repeated substring" in desc:
                context.recommendations.append(
                    Recommendation(
                        severity=pattern.severity.value,
                        message=f"Avoid repeating words or blocks of characters."
                    )
                )

        # Check for dictionary matches
        exact_matches = [m for m in context.dictionary_matches if m.is_exact_match]
        if exact_matches:
            context.recommendations.append(
                Recommendation(
                    severity="High",
                    message="Your password is a common word or a simple variation of one. Avoid using common dictionary words."
                )
            )
        elif context.dictionary_matches:
            context.recommendations.append(
                Recommendation(
                    severity="Medium",
                    message="Your password contains common dictionary words. Consider using unrelated words or a passphrase."
                )
            )

        # Remove duplicate recommendations
        unique_recs = []
        seen = set()
        for rec in context.recommendations:
            if rec.message not in seen:
                seen.add(rec.message)
                unique_recs.append(rec)
        
        context.recommendations = unique_recs
