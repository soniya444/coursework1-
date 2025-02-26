# coursework1-
import requests
import logging
import time

class VulnerabilityScannerCLI:
    def __init__(self):
        self.target_url = ""
        self.vulnerabilities = []
        self.logger = self.setup_logger()
        self.auth = None
        self.headers = {}

    def setup_logger(self):
        logger = logging.getLogger("VulnerabilityScanner")
        logger.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler("scan_report.log")
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        return logger

    def prompt_for_target_url(self):
        self.target_url = input("Enter the target URL: ").strip()
        if not self.target_url:
            self.logger.warning("No URL provided. Exiting program.")
            return False
        return True

    def prompt_for_scan_type(self):
        scan_type = input("Enter scan type (XSS, SQL, Directory, or Custom): ").strip().lower()
        if scan_type not in ["xss", "sql", "directory", "custom"]:
            self.logger.error(f"Invalid scan type entered: {scan_type}")
            return None
        return scan_type

    def prompt_for_authentication(self):
        use_auth = input("Do you need authentication for this site? (yes/no): ").strip().lower()
        if use_auth == "yes":
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()
            self.auth = (username, password)
            self.logger.info("Basic authentication set.")
        elif use_auth == "no":
            self.auth = None
            self.logger.info("No authentication required.")
        else:
            self.logger.warning("Invalid input. Assuming no authentication.")

    def prompt_for_custom_payload(self):
        custom_payload = input("Enter your custom payload (or leave empty to use default): ").strip()
        return custom_payload if custom_payload else None

    def measure_response_time(self, url, method="GET", data=None):
        start_time = time.time()
        try: 
            if method == "GET":
                response = requests.get(url, auth=self.auth, headers=self.headers)
            elif method == "POST":
                response = requests.post(url, data=data, auth=self.auth, headers=self.headers)
            response_time = time.time() - start_time
            self.logger.info(f"Response time: {response_time:.4f} seconds")
            return response, response_time
        except requests.RequestException as e:
            self.logger.error(f"Request failed: {e}")
            return None, None

    def start_scan(self):
        if not self.prompt_for_target_url():
            return
        
        self.prompt_for_authentication()

        scan_type = self.prompt_for_scan_type()
        if scan_type is None:
            return
        
        self.logger.info(f"Starting {scan_type.upper()} scan on {self.target_url}...")
        if scan_type == "xss":
            self.scan_xss()
        elif scan_type == "sql":
            self.scan_sql_injection()
        elif scan_type == "directory":
            self.scan_directory_traversal()
        elif scan_type == "custom":
            self.scan_custom_payload()

        self.show_vulnerabilities()

    def scan_xss(self):
        payload = "<script>alert('XSS')</script>"
        self.logger.info(f"Testing for XSS using payload: {payload}")
        response, response_time = self.measure_response_time(self.target_url, "POST", {"input": payload})
        if response and payload in response.text:
            self.vulnerabilities.append("XSS vulnerability found!")
            self.logger.info("XSS vulnerability found!")
        else:
            self.logger.info("No XSS vulnerability found.")

    def scan_sql_injection(self):
        payload = "' OR '1'='1"
        self.logger.info(f"Testing for SQL injection using payload: {payload}")
        response, response_time = self.measure_response_time(self.target_url + "?id=" + payload)
        if response and "error" in response.text:
            self.vulnerabilities.append("SQL injection vulnerability found!")
            self.logger.info("SQL injection vulnerability found!")
        else:
            self.logger.info("No SQL injection vulnerability found.")

    def scan_directory_traversal(self):
        payload = "../../../../etc/passwd"
        self.logger.info(f"Testing for Directory traversal using payload: {payload}")
        response, response_time = self.measure_response_time(self.target_url + payload)
        if response and "root:x" in response.text:
            self.vulnerabilities.append("Directory traversal vulnerability found!")
            self.logger.info("Directory traversal vulnerability found!")
        else:
            self.logger.info("No directory traversal vulnerability found.")

    def scan_custom_payload(self):
        custom_payload = self.prompt_for_custom_payload()
        if not custom_payload:
            self.logger.warning("No custom payload provided. Skipping custom scan.")
            return
        self.logger.info(f"Testing for vulnerability using custom payload: {custom_payload}")
        response, response_time = self.measure_response_time(self.target_url, "POST", {"input": custom_payload})
        if response and custom_payload in response.text:
            self.vulnerabilities.append("Custom vulnerability found!")
            self.logger.info("Custom vulnerability found!")
        else:
            self.logger.info("No custom vulnerability found.")

    def show_vulnerabilities(self):
        if self.vulnerabilities:
            self.logger.info("Vulnerabilities found:")
            for vuln in self.vulnerabilities:
                self.logger.info(f"- {vuln}")
        else:
            self.logger.info("No vulnerabilities found.")

    def generate_report(self):
        self.logger.info("Generating scan report...")
        with open("scan_report.txt", "w") as file:
            file.write("Scan Report\n")
            file.write("="*50 + "\n")
            file.write(f"Target URL: {self.target_url}\n")
            file.write(f"Scan Type: {'XSS' if 'XSS' in self.vulnerabilities else 'SQL' if 'SQL' in self.vulnerabilities else 'Directory' if 'Directory' in self.vulnerabilities else 'Custom'}\n")
            file.write(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n")
            file.write("="*50 + "\n")
            for vuln in self.vulnerabilities:
                file.write(f"- {vuln}\n")
        self.logger.info("Scan report saved to 'scan_report.txt'.")

    def start_multiple_scans(self):
        while True:
            self.start_scan()
            self.generate_report()
            again = input("\nWould you like to scan another URL? (yes/no): ").strip().lower()
            if again != "yes":
                self.logger.info("Exiting the program.")
                break


# Main application
if __name__ == "__main__":
    scanner = VulnerabilityScannerCLI()
    scanner.start_multiple_scans()
