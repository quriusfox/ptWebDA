import requests

from .helpers import Log
from .http import HTTPRequest, HTTPRequestParser


class HeadersTest:
    def __init__(
        self, target: str | None, request_file_path: str | None = None, https: bool = True
    ) -> None:
        self.target = target
        self.http_request: HTTPRequest | None = None

        if self.target is None:
            if request_file_path:
                parser = HTTPRequestParser(request_file_path, https)
                self.http_request = parser.parse()

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
            response = requests.Response()

            if self.http_request is not None:
                response = requests.get(
                    (
                        "https://" + self.http_request.host + self.http_request.path
                        if self.http_request.https
                        else "http://" + self.http_request.host + self.http_request.path
                    ),
                    cookies=self.http_request.cookies,
                    data=self.http_request.data,
                )
            else:
                if self.target is not None:
                    response = requests.get(self.target)
                else:
                    raise ValueError("Target cannot be 'None'")

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
