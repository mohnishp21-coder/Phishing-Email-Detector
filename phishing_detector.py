"""
Phishing Email Detector
A beginner-friendly, offline, rule-based educational tool.
It analyses text supplied by the user; it never opens links or contacts servers.
"""

import re
from urllib.parse import urlparse

URGENT_PHRASES = [
    "act now", "urgent", "immediately", "within 24 hours",
    "expires today", "account will be suspended", "limited time",
    "final warning", "verify immediately",
]
CREDENTIAL_PHRASES = [
    "password", "one-time password", " otp", "login details",
    "sign in", "verify your account", "security code",
]
MONEY_OR_REWARD_PHRASES = [
    "you have won", "claim your prize", "free gift",
    "scholarship approved", "cash reward", "payment failed",
]
PRESSURE_PHRASES = [
    "do not tell", "do not contact", "keep this confidential",
    "avoid contacting", "only use this link",
]

URL_RE = re.compile(r"https?://[^\s<>\]\[()\"']+", re.IGNORECASE)


def extract_urls(text):
    """Return URLs found in text. URLs are inspected as text only."""
    return URL_RE.findall(text or "")


def analyse_email(subject, sender, body):
    """Return a risk score, findings, and a cautious risk label."""
    combined = f"{subject}\n{sender}\n{body}".lower()
    findings = []
    score = 0

    checks = [
        (URGENT_PHRASES, 2, "Urgent or time-pressure language"),
        (CREDENTIAL_PHRASES, 3, "Request or mention of passwords, OTPs, or sign-in details"),
        (MONEY_OR_REWARD_PHRASES, 2, "Unexpected reward, payment, or prize language"),
        (PRESSURE_PHRASES, 3, "Discourages independent verification"),
    ]

    for phrases, points, description in checks:
        matched = [phrase.strip() for phrase in phrases if phrase in combined]
        if matched:
            score += points
            findings.append(f"{description}: {', '.join(matched)}")

    urls = extract_urls(body)
    if urls:
        findings.append(f"Contains {len(urls)} web link(s); inspect them carefully without opening suspicious links.")
        for url in urls:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if parsed.scheme.lower() == "http":
                score += 1
                findings.append(f"Unencrypted HTTP link detected: {host or url}")
            if host and (host.startswith("xn--") or "@" in url):
                score += 2
                findings.append(f"Potentially deceptive URL formatting: {host}")

    if sender and not re.search(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender.strip()):
        score += 1
        findings.append("Sender field does not look like a standard email address.")

    if not findings:
        findings.append("No configured warning patterns were detected. This does not prove the email is safe.")

    if score >= 7:
        level = "HIGH"
    elif score >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "findings": findings,
        "urls": urls,
    }


def main():
    print("=" * 58)
    print("             PHISHING EMAIL DETECTOR")
    print("        Offline educational security checker")
    print("=" * 58)
    subject = input("Email subject: ").strip()
    sender = input("Sender email address: ").strip()
    print("Paste the email body. Press Enter on an empty line to finish:")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line:
            break
        lines.append(line)
    result = analyse_email(subject, sender, "\n".join(lines))

    print("\n" + "-" * 58)
    print(f"Risk level : {result['level']}")
    print(f"Risk score : {result['score']}")
    print("Findings:")
    for item in result["findings"]:
        print(f"  - {item}")
    print("\nSafety advice:")
    print("  - Do not share passwords, OTPs, or identity documents.")
    print("  - Verify requests through an official website or known contact.")
    print("  - Do not open suspicious links or attachments.")
    print("  - Report suspicious messages to your organisation's IT team.")
    print("\nNote: This is a simple rule-based checker, not a guarantee.")
    print("A LOW result does not mean an email is safe.")
    print("-" * 58)


if __name__ == "__main__":
    main()
