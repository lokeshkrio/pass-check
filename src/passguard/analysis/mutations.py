from passguard.context import AnalysisContext

# Common leetspeak substitutions
LEETSPEAK_MAP = {
    "0": ["o"],
    "1": ["i", "l"],
    "3": ["e"],
    "4": ["a"],
    "5": ["s"],
    "7": ["t"],
    "8": ["b"],
    "@": ["a"],
    "$": ["s"],
    "!": ["i"],
    "+": ["t"],
}

class LeetspeakNormalizer:
    def analyze(self, context: AnalysisContext) -> None:
        if not context.password:
            return

        normalized = ""
        substituted = False
        
        for char in context.password:
            if char in LEETSPEAK_MAP:
                # To keep it simple, we just take the first standard character mapped
                normalized += LEETSPEAK_MAP[char][0]
                substituted = True
            else:
                normalized += char
                
        if substituted:
            if normalized not in context.normalized_passwords:
                context.normalized_passwords.append(normalized)
