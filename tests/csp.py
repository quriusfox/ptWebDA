import requests
from helpers import Print


class CSPTest:
    def __init__(self, target: str) -> None:
        self.target = target

    def test_info(self):
        Print.info(f"Test info:\n")
        print("\tTest name : CSPTest")
        print(f"\tTarget    : {self.target}\n")

    def run_test(self):
        Print.progress("Analyzing CSP directives")
        self.test_info()

        try:
            response: requests.Response = requests.get(self.target)

            for key, value in response.headers.items():
                if key == "Content-Security-Policy" or key == "content-security-policy":
                    directives = value.split("; ")

                    for directive in directives:
                        if "unsafe" in directive.lower():
                            Print.warning(directive)
                            continue

                        Print.info(directive)

        except requests.exceptions.RequestException as e:
            Print.error(f"Error occurred: {e}")

        Print.success("Test finished successfully")
