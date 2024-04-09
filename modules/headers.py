import argparse
import requests

from typing import NamedTuple
from .helpers import Log
from .basemodule import BaseModule, PTVuln

# region Constants
INFO_HEADERS: list[str] = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
]

MISSING_HEADERS: list[str] = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "strict-transport-security",
    "permissions-policy",
]

CACHE_HEADERS: list[str] = [
    "cache-control",
    "pragma",
    "last-modified",
    "expires",
    "etag",
]

PT_VULN_CODES: dict[str, str] = {
    # Missing headers:
    "content-security-policy": "PTV-WEB-MISSINGHEADER-CSP",
    "x-frame-options": "PTV-WEB-MISSINGHEADER-XFRAMEOPTIONS",
    "x-content-type-options": "PTV-WEB-MISSINGHEADER-XCONTENTTYPEOPTIONS",
    "referrer-policy": "PTV-WEB-MISSINGHEADER-REFERRERPOLICY",
    "strict-transport-security": "PTV-WEB-MISSINGHEADER-HSTS",
    "permissions-policy": "PTV-WEB-PERMISSIONSPOLICY",
    # Headers leaking information:
    "server": "PTV-WEB-LEAKINGHEADER-SERVER",
    "x-powered-by": "PTV-WEB-LEAKINGHEADER-XPOWEREDBY",
    "x-aspnet-version": "PTV-WEB-LEAKINGHEADER-XASPNETVERSION",
    "x-aspnetmvc-version": "PTV-WEB-LEAKINGHEADER-XASPNETMVCVERSION",
}

# endregion


# region Structures
class Header(NamedTuple):
    """
    This structure's purpose is to represent HTTP header and its contents with addition to providing
    a finding code from the PT_VULN_CODES dictionary.
    """

    name: str
    code: str | None
    value: str | None


class HeadersResults(NamedTuple):
    """
    Structure that holds HTTP headers and their values. Divided into three categories
    of HTTP headers.
    """

    missing_headers: list[Header]
    headers_leaking_info: list[Header]
    cache_headers: list[Header]


# endregion


# region Main module class
class HeadersTest(BaseModule[HeadersResults]):
    """
    This class represents the HTTP headers module. This module evaluates security configuration
    of HTTP headers that are returned (or not returned) by the web server. The module is very simple
    in terms of implementation, however, it still provides a valuable information for a pentester
    during an engagement.

    Args:
        BaseModule (_type_): This class is a child class to the BaseModule class. The test returns
        a structure of type "HeadersResults".
    """

    def __init__(
        self, target: str | None, request_file_path: str | None = None, https: bool = True
    ) -> None:
        """
        Constructor for the HTTP headers module. At first the target setup is performed. Then the
        constructor defines some constat lists of HTTP headers that are used throughout the module's
        runtime.

        Args:
            target (str | None): URL of the target e.g. https://www.example.com/login
            request_file_path (str | None, optional): Path to a file with HTTP request exported
            e.g. from Burp Suite. Defaults to None as the primary method is "target".
            https (bool, optional): Indication of whether the request from the file is supposed to
            be sent via HTTPS. Defaults to True.
        """
        super().__init__(target, request_file_path, https)

        # Penterep compatibility
        self.request_text: bytes = b""
        self.response_text: bytes = b""

        # Results
        self.results: HeadersResults | None = None
        self.evaluation: list[PTVuln] | None = None

    def run(self) -> None:
        self.print_info()
        self.results = self.test()
        self.evaluate()
        self.print_results()

        Log.success("Test finished successfully")

    def print_info(self) -> None:
        """
        Provides basic information about current test's setup parameters.
        """
        Log.progress(f"Test info:\n")
        print("\tTest name : HeadersTest")
        print(f"\tTarget    : {self.target}\n")

    def test(self) -> HeadersResults:
        """
        Sends prepared HTTP request to the target endpoint and retireves HTTP headers that are
        missing from the implementation, are present and leak information and headers containing
        caching information.

        Returns:
            HeadersResults: Strucuture holding HTTP headers and, in case of headers that leak
            information and cache headers, the potentially sensitive information as well.
        """
        res_missing_headers: list[Header] = []
        res_headers_leaking_info: list[Header] = []
        res_cache_headers: list[Header] = []

        # Dict to store normalized headers
        lowercase_headers: dict[str, str] = {}

        try:
            # Send the final prepared request in the constructor
            response: requests.Response = requests.Session().send(self.prepared_request.prepare())

            # Save request and response data for the PTVuln stucture
            self.save_request_text(response.request)
            self.save_response_text(response)

            # Normalize the response headers to lowercase
            for key, value in response.headers.items():
                lowercase_headers[key.lower()] = value

            # Collect headers that are missing and should be implemented
            for header in MISSING_HEADERS:
                if header not in lowercase_headers:
                    res_missing_headers.append(Header(header, PT_VULN_CODES[header], None))

            # Collect headers that are present and potentially contain sensitive infomarion
            for header in INFO_HEADERS:
                if header in lowercase_headers:
                    res_headers_leaking_info.append(
                        Header(header, PT_VULN_CODES[header], lowercase_headers[header])
                    )

            # Collect headers that are present and potentially contain useful caching information
            for header in CACHE_HEADERS:
                if header in lowercase_headers:
                    res_cache_headers.append(Header(header, None, lowercase_headers[header]))

        except requests.exceptions.RequestException as e:
            Log.error(f"Error occurred: {e}")

        return HeadersResults(res_missing_headers, res_headers_leaking_info, res_cache_headers)

    def evaluate(self) -> None:
        """
        Function takes the data from HeadersResults structure and transforms it to Penterep
        compatible PTVuln structure.
        """
        if self.results is None:
            return None

        res: list[PTVuln] = []

        for header in self.results.missing_headers:
            if header.code is None:
                Log.error(f"Header in findings {header.name} does not have a PT_VULN_CODE!")
                continue

            res.append(PTVuln(header.code, self.request_text, self.response_text))

        self.evaluation = res

    def print_results(self) -> None:
        """
        Function prints the module's output. This does not have any impact on the Penterep
        integration. This function solely prints output to the terminal for the penetration tester.
        """
        if self.results is None:
            Log.error("Results cannot be printed! Value of results is None")
            return None

        Log.info("Missing headers:")
        for header in self.results.missing_headers:
            print(f"\t{header.name}")

        Log.info("Headers potentially leaking info:")
        for header in self.results.headers_leaking_info:
            print(f"\t{header.name}: {header.value}")

    def json(self) -> None:
        raise NotImplementedError

    @staticmethod
    def add_subparser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore
        raise NotImplementedError


# endregion
