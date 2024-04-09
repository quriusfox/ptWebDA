import argparse
import requests

from typing import NamedTuple
from .helpers import Log
from .basemodule import BaseModule


# region Structures
class HeadersResults(NamedTuple):
    """
    Structure that holds HTTP headers and their values. Divided into three categories
    of HTTP headers.
    """

    missing_headers: list[str]
    headers_leaking_info: dict[str, str]
    cache_headers: dict[str, str]


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

        self.INFO_HEADERS: list[str] = [
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version",
        ]

        self.MISSING_HEADERS: list[str] = [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "strict-transport-security",
            "permissions-policy",
        ]

        self.CACHE_HEADERS: list[str] = [
            "cache-control",
            "pragma",
            "last-modified",
            "expires",
            "etag",
        ]

        self.results: HeadersResults | None = None

    def run(self) -> None:
        self.print_info()
        self.results = self.test()
        self.print_results()

        Log.success("Test finished successfully")

    def test(self) -> HeadersResults:
        """
        Sends prepared HTTP request to the target endpoint and retireves HTTP headers that are
        missing from the implementation, are present and leak information and headers containing
        caching information.

        Returns:
            HeadersResults: Strucuture holding HTTP headers and, in case of headers that leak
            information and cache headers, the potentially sensitive information as well.
        """
        res_missing_headers: list[str] = []
        res_headers_leaking_info: dict[str, str] = {}
        res_cache_headers: dict[str, str] = {}

        # Dict to store normalized headers
        lowercase_headers: dict[str, str] = {}

        try:
            # Send the final prepared request in the constructor
            response: requests.Response = requests.Session().send(self.prepared_request.prepare())

            # Normalize the response headers to lowercase
            for key, value in response.headers.items():
                lowercase_headers[key.lower()] = value

            # Collect headers that are missing and should be implemented
            for header in self.MISSING_HEADERS:
                if header not in lowercase_headers:
                    res_missing_headers.append(header)

            # Collect headers that are present and potentially contain sensitive infomarion
            for header in self.INFO_HEADERS:
                if header in lowercase_headers:
                    res_headers_leaking_info[header] = lowercase_headers[header]

            # Collect headers that are present and potentially contain useful caching information
            for header in self.CACHE_HEADERS:
                if header in lowercase_headers:
                    res_cache_headers[header] = lowercase_headers[header]

        except requests.exceptions.RequestException as e:
            Log.error(f"Error occurred: {e}")

        return HeadersResults(res_missing_headers, res_headers_leaking_info, res_cache_headers)

    def evaluate(self) -> None:
        raise NotImplementedError

    def print_info(self) -> None:
        """
        Prints basic test info.
        """
        Log.progress(f"Test info:\n")
        print("\tTest name : HeadersTest")
        print(f"\tTarget    : {self.target}\n")

    def print_results(self) -> None:
        if self.results is None:
            Log.error("Results cannot be printed! Value of results is None")
            return None

        Log.info("Missing headers")

        for res in self.results.missing_headers:
            print(f"\t{res}")

        Log.info("Headers potentially leaking info")

        for key, value in self.results.headers_leaking_info.items():
            print(f"\t{key}: {value}")

    def json(self) -> None:
        raise NotImplementedError

    @staticmethod
    def add_subparser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore
        raise NotImplementedError


# endregion
