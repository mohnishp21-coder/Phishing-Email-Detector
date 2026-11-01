import unittest
from phishing_detector import analyse_email, extract_urls


class PhishingDetectorTests(unittest.TestCase):
    def test_high_risk_message(self):
        result = analyse_email(
            "URGENT: account will be suspended",
            "security@example.com",
            "Verify your account immediately. Enter your password and OTP. "
            "Do not contact the office. http://example.test/login",
        )
        self.assertEqual(result["level"], "HIGH")
        self.assertGreaterEqual(result["score"], 7)

    def test_no_warning_patterns(self):
        result = analyse_email(
            "Class timetable",
            "teacher@example.edu",
            "The updated timetable is available on the student portal.",
        )
        self.assertEqual(result["level"], "LOW")

    def test_url_extraction(self):
        urls = extract_urls("Visit https://example.com and http://test.example/page")
        self.assertEqual(len(urls), 2)


if __name__ == "__main__":
    unittest.main()
