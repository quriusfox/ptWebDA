import requests

from helpers import Log


class HeadersTest:
    def __init__(self, target: str):
        self.target: str = target
        self.info_headers: list[str] = [
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version",
        ]
        self.missing_headers: list[str] = [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "strict-transport-security",
            "permissions-policy",
        ]

    def run(self):
        Log.progress("Testing missing headers:")
        self.test_info()

        try:
            response: requests.Response = requests.get(self.target)

            lowercase_headers: dict[str, str] = {}

            # Normalize the response headers to lowercase
            for key, value in response.headers.items():
                lowercase_headers[key.lower()] = value

            Log.info("Missing headers:")

            for header in self.missing_headers:
                if header not in lowercase_headers:
                    print(f"\t{header}")

            Log.info("Headers potentialy leaking information:")

            for header in self.info_headers:
                if header in lowercase_headers:
                    print(f"\t{header}: {lowercase_headers[header]}")

        except requests.exceptions.RequestException as e:
            Log.error(f"Error occurred: {e}")

        Log.success("Test finished successfully")

    def test_info(self):
        Log.info(f"Test info:\n")
        print("\tTest name : HeadersTest")
        print(f"\tTarget    : {self.target}\n")
