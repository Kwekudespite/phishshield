import re
from urllib.parse import urlparse

# ---------------- URL ANALYZER ----------------
def analyze_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url)

    if parsed.scheme == "http":
        score += 15
        reasons.append("Uses insecure HTTP protocol")

    if re.search(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
        score += 20
        reasons.append("Uses IP address instead of domain")

    suspicious_keywords = ["login", "verify", "update", "secure",
                           "bank", "account", "confirm"]

    for word in suspicious_keywords:
        if word in url.lower():
            score += 10
            reasons.append(f"Contains suspicious keyword: '{word}'")

    if parsed.netloc.count('.') > 3:
        score += 10
        reasons.append("Too many subdomains")

    if len(url) > 75:
        score += 10
        reasons.append("URL is unusually long")

    suspicious_tlds = [".xyz", ".top", ".ru", ".tk"]
    for tld in suspicious_tlds:
        if parsed.netloc.endswith(tld):
            score += 15
            reasons.append(f"Suspicious domain extension: {tld}")

    return min(score, 100), reasons


# ---------------- EMAIL ANALYZER ----------------
def analyze_email(text):
    score = 0
    reasons = []

    urgent_words = ["urgent", "immediately", "act now", "limited time"]
    threat_words = ["account suspended", "verify your account", "password required"]

    for word in urgent_words:
        if word in text.lower():
            score += 15
            reasons.append(f"Urgency phrase detected: '{word}'")

    for word in threat_words:
        if word in text.lower():
            score += 20
            reasons.append(f"Threat phrase detected: '{word}'")

    if re.search(r"http[s]?://", text):
        score += 15
        reasons.append("Contains external link")

    return min(score, 100), reasons


# ---------------- PASSWORD CHECKER ----------------
def check_password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 25
    if re.search(r"[A-Z]", password):
        score += 25
    if re.search(r"[a-z]", password):
        score += 15
    if re.search(r"[0-9]", password):
        score += 15
    if re.search(r"[!@#$%^&*()_+]", password):
        score += 20

    return min(score, 100)
