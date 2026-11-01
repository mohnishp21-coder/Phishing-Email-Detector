# Phishing Email Detector

**Student project:** Python Cybersecurity Mini Project  
**Student:** P. Mohnish

## 1. Project overview
This beginner-friendly Python program checks email subject, sender address, and body text for common phishing warning signs. It uses a small, transparent rule-based scoring system and prints a LOW, MEDIUM, or HIGH risk indicator.

The tool works offline. It does not open URLs, download attachments, send email, or contact external services.

## 2. Features
- Checks for urgency and pressure language.
- Flags requests or references involving passwords, OTPs, and sign-in details.
- Notices unexpected prize, reward, or payment language.
- Flags language discouraging independent verification.
- Extracts web links and notes HTTP links.
- Displays findings and safe next steps.
- Includes automated unit tests and fictional sample messages.

## 3. Requirements
- Python 3.8 or newer
- No third-party packages required

## 4. Run the project
Open a terminal in this folder and run:

```bash
python phishing_detector.py
```

Enter a subject, sender email address, and body. Finish the body by pressing Enter on a blank line.

## 5. Run tests

```bash
python -m unittest -v
```

Expected result: 3 tests pass.

## 6. Example test message
Subject: URGENT: Account will be suspended  
Sender: security@example.test  
Body: Verify your account immediately. Enter your password and OTP. Do not contact the office. http://example.test/login

Expected outcome: HIGH risk, with several warning findings.

## 7. Risk scoring
The score is a simple educational heuristic:
- Urgency language: +2
- Credential / OTP language: +3
- Unexpected reward or payment language: +2
- Discouraging verification: +3
- HTTP link: +1
- Potentially deceptive URL formatting: +2
- Sender field not in a standard email format: +1

Labels:
- LOW: 0–2
- MEDIUM: 3–6
- HIGH: 7 or more

## 8. Limitations
- A rule-based detector can miss new or cleverly worded phishing messages.
- Legitimate messages may contain words that trigger warnings (false positives).
- The tool does not verify sender identity, email authentication headers, domain ownership, or website reputation.
- It does not inspect attachments.
- A LOW result does not prove that an email is safe. Always verify important requests independently.

## 9. Safety and privacy
Use fictional or non-sensitive examples for demonstrations. Never paste real passwords, OTPs, private student information, or confidential emails into this project. Do not open suspicious links to test them.

## 10. Suggested GitHub repository contents

```text
Phishing-Email-Detector/
├── phishing_detector.py
├── test_phishing_detector.py
├── sample_emails.txt
└── README.md
```

## 11. Project declaration
This is an educational mini project created to demonstrate basic Python programming and defensive cybersecurity awareness. It is not a replacement for professional email security software or an authorised security review.
