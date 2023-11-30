import requests

from helpers import Print


class HeadersTest():
    def __init__(self, target: str):
        self.target          : str  = target
        self.info_headers    : list = [
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version"
        ]
        self.missing_headers : list = [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "strict-transport-security",
            "permissions-policy"
        ]


    def test_info(self):
        Print.info(f"Test info:\n")
        print("\tTest name : HeadersTest")
        print(f"\tTarget    : {self.target}\n")


    def run_test(self):
        Print.progress("Testing missing headers:")
        self.test_info()

        try:
            r: requests.Response = requests.get(self.target)

            lowercase_headers: dict = {}
            
            # Normalize the response headers to lowercase
            for key, value in r.headers.items():
                lowercase_headers[key.lower()] = value

            Print.info("Missing headers:")

            for header in self.missing_headers:
                if header not in lowercase_headers:
                    print(f"\t{header}")
            
            Print.info("Headers potentialy leaking information:")
            
            for header in self.info_headers:
                if header in lowercase_headers:
                    print(f"\t{header}: {lowercase_headers[header]}")

        except requests.exceptions.RequestException as e:
            Print.error(f"Error occurred: {e}")

        Print.success("Test finished successfully")
