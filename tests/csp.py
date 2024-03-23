import requests
from helpers import Log


class CSPTest:
    def __init__(self, target: str) -> None:
        self.target = target

    def run(self):
        Log.progress("Analyzing CSP directives")
        self.test_info()

        try:
            response: requests.Response = requests.get(self.target)

            for key, value in response.headers.items():
                if key == "Content-Security-Policy" or key == "content-security-policy":
                    directives = value.split("; ")

                    for directive in directives:
                        if "unsafe" in directive.lower():
                            Log.warning(directive)
                            continue

                        Log.info(directive)

        except requests.exceptions.RequestException as e:
            Log.error(f"Error occurred: {e}")

        Log.success("Test finished successfully")

    def test_info(self):
        Log.info(f"Test info:\n")
        print("\tTest name : CSPTest")
        print(f"\tTarget    : {self.target}\n")
