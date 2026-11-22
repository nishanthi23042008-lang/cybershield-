"""Simple, explainable checks for suspicious message wording."""

MAX_MESSAGE_LENGTH = 5000

# Each group adds points once, even if its words appear more than once.
INDICATORS = [
    ("urgent", 20, ("urgent", "immediately", "act now", "expires today", "final warning"),
     "The message creates urgency or pressure to act quickly."),
    ("credentials", 30, ("password", "one-time code", "verification code", "login details", "sign in"),
     "The message mentions passwords, sign-in details, or verification codes."),
    ("payment", 25, ("payment", "bank account", "credit card", "wire transfer", "pay a fee"),
     "The message asks about money or payment details."),
    ("prize", 20, ("you won", "winner", "claim your prize", "free gift", "lottery"),
     "The message promises a prize or unexpected reward."),
    ("threat", 20, ("account will be closed", "account suspended", "legal action", "arrest warrant"),
     "The message uses a threat or consequence to prompt action."),
]


def analyze_message(value):
    """Return a score and reasons, or (None, error) for invalid input."""
    if len(value) > MAX_MESSAGE_LENGTH:
        return None, f"Message must be {MAX_MESSAGE_LENGTH} characters or fewer."

    lowered = value.lower()
    reasons = [description for _name, _points, phrases, description in INDICATORS
               if any(phrase in lowered for phrase in phrases)]
    score = sum(points for _name, points, phrases, _description in INDICATORS
                if any(phrase in lowered for phrase in phrases))
    score = min(score, 100)

    if score >= 50:
        level = "Higher indicator level"
    elif score >= 20:
        level = "Some indicators"
    else:
        level = "Few indicators"

    if not reasons:
        reasons.append("These basic wording checks did not find the indicators they look for.")

    return {
        "risk_score": score,
        "level": level,
        "reasons": reasons,
        "notice": "These are wording indicators only, not a definitive safety verdict. No links were opened.",
    }, None
