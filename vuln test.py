import unittest
from unittest.mock import patch, MagicMock
from vuln import VulnerabilityScannerCLI  # Assuming the script is saved as vulnerability_scanner.py
class TestVulnerabilityScannerCLI(unittest.TestCase):
    def setUp(self):
        self.scanner = VulnerabilityScannerCLI()

    @patch("builtins.input", side_effect=["http://test.com"])
    def test_prompt_for_target_url(self, mock_input):
        self.assertTrue(self.scanner.prompt_for_target_url())
        self.assertEqual(self.scanner.target_url, "http://test.com")
    
    @patch("builtins.input", side_effect=[""])
    def test_prompt_for_target_url_empty(self, mock_input):
        self.assertFalse(self.scanner.prompt_for_target_url())

    @patch("builtins.input", side_effect=["XSS"])
    def test_prompt_for_scan_type_valid(self, mock_input):
        self.assertEqual(self.scanner.prompt_for_scan_type(), "xss")

    @patch("builtins.input", side_effect=["invalid"])
    def test_prompt_for_scan_type_invalid(self, mock_input):
        self.assertIsNone(self.scanner.prompt_for_scan_type())
    
    @patch("builtins.input", side_effect=["yes", "admin", "password"])
    def test_prompt_for_authentication(self, mock_input):
        self.scanner.prompt_for_authentication()
        self.assertEqual(self.scanner.auth, ("admin", "password"))
    
    @patch("builtins.input", side_effect=["no"])
    def test_prompt_for_authentication_no_auth(self, mock_input):
        self.scanner.prompt_for_authentication()
        self.assertIsNone(self.scanner.auth)
    
    @patch("requests.get")
    def test_measure_response_time_get(self, mock_get):
        mock_response = MagicMock()
        mock_response.text = "Test Response"
        mock_get.return_value = mock_response
        response, response_time = self.scanner.measure_response_time("http://test.com")
        self.assertIsNotNone(response)
        self.assertGreaterEqual(response_time, 0)
    
    @patch("requests.post")
    def test_measure_response_time_post(self, mock_post):
        mock_response = MagicMock()
        mock_response.text = "Test Response"
        mock_post.return_value = mock_response
        response, response_time = self.scanner.measure_response_time("http://test.com", "POST", {"input": "test"})
        self.assertIsNotNone(response)
        self.assertGreaterEqual(response_time, 0)
    
    @patch("builtins.input", side_effect=["<script>alert('XSS')</script>"])
    def test_prompt_for_custom_payload(self, mock_input):
        self.assertEqual(self.scanner.prompt_for_custom_payload(), "<script>alert('XSS')</script>")

    @patch("builtins.input", side_effect=[""])
    def test_prompt_for_custom_payload_empty(self, mock_input):
        self.assertIsNone(self.scanner.prompt_for_custom_payload())

    @patch("requests.post")
    def test_scan_xss_vulnerable(self, mock_post):
        mock_response = MagicMock()
        mock_response.text = "<script>alert('XSS')</script>"
        mock_post.return_value = mock_response
        self.scanner.target_url = "http://test.com"
        self.scanner.scan_xss()
        self.assertIn("XSS vulnerability found!", self.scanner.vulnerabilities)
    
    @patch("requests.get")
    def test_scan_sql_injection_vulnerable(self, mock_get):
        mock_response = MagicMock()
        mock_response.text = "error"
        mock_get.return_value = mock_response
        self.scanner.target_url = "http://test.com"
        self.scanner.scan_sql_injection()
        self.assertIn("SQL injection vulnerability found!", self.scanner.vulnerabilities)

    @patch("requests.get")
    def test_scan_directory_traversal_vulnerable(self, mock_get):
        mock_response = MagicMock()
        mock_response.text = "root:x"
        mock_get.return_value = mock_response
        self.scanner.target_url = "http://test.com"
        self.scanner.scan_directory_traversal()
        self.assertIn("Directory traversal vulnerability found!", self.scanner.vulnerabilities)

if __name__ == "__main__":
    unittest.main()
