import argparse
import requests

from typing import NamedTuple
from .utils.helpers import Log
from .basemodule import BaseModule

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
    "permissions-policy": "PTV-WEB-MISSINGHEADER-PERMISSIONSPOLICY",
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
        self,
        target: str | None,
        request_file_path: str | None,
        proxy: str | None,
        https: bool = True,
    ) -> None:
        """
        Constructor for the HTTP headers module, mainly consisting of the target's initial setup.

        Args:
            target (str | None): URL of the target e.g. https://www.example.com/login
            request_file_path (str | None, optional): Path to a file with HTTP request exported
            e.g. from Burp Suite. Defaults to None as the primary method is "target".
            https (bool, optional): Indication of whether the request from the file is supposed to
            be sent via HTTPS. Defaults to True.
        """
        super().__init__(target, request_file_path, proxy, https)

        # Results
        self.results: HeadersResults | None = None

    def run(self) -> bool:
        self.print_info()
        Log.progress("Running module")
        self.results = self.test()

        if self.results is None:
            return False

        return True

    def print_info(self) -> None:
        """
        Provides basic information about current test's setup parameters.
        """
        Log.progress(f"Test info:\n")
        Log.print("Test name : HeadersTest")
        Log.print(
            f"Target:   : {self.target if self.target is not None else self.prepared_request.url}"
        )
        Log.print(f"HTTPS     : {self.https}")
        Log.print(f"Proxies   : {self.proxies}\n")

    def test(self) -> HeadersResults | None:
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
            response: requests.Response = requests.Session().send(
                self.prepared_request.prepare(), proxies=self.proxies, verify=self.verify
            )

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
            return None

        return HeadersResults(res_missing_headers, res_headers_leaking_info, res_cache_headers)

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
            Log.print(f"{header.name}")

        Log.info("Headers potentially leaking info:")
        for header in self.results.headers_leaking_info:
            Log.print(f"{header.name}: {header.value}")

    def json(self) -> str | None:
        """
        Function iterates over the module's results and serializes them into
        Penterep JSON structures.

        Returns:
            str | None: String representing the modules JSON output
        """
        if self.results is None:
            return None

        for header in self.results.missing_headers:
            if header.code is None:
                Log.error(f"Header in findings {header.name} does not have a PT_VULN_CODE!")
                continue

            self.ptjsonlib.add_vulnerability(
                header.code, self.request_text.decode(), self.response_text.decode()
            )

        for header in self.results.headers_leaking_info:
            if header.code is None:
                Log.error(f"Header in findings {header.name} does not have a PT_VULN_CODE!")
                continue

            self.ptjsonlib.add_vulnerability(
                header.code, self.request_text.decode(), self.response_text.decode()
            )

        return self.ptjsonlib.get_result_json()

    @staticmethod
    def add_subparser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore
        modname = __name__.split(".")[-1]
        parser = subparsers.add_parser(modname, add_help=True)  # type: ignore

        if not isinstance(parser, argparse.ArgumentParser):
            raise TypeError  # IDE typing

        parser.add_argument("-u", "--url", help="URL to check headers for")
        parser.add_argument(
            "-f", "--file", "-f", help="Path to the file used by the modules (optional)"
        )
        parser.add_argument(
            "-p", "--proxy", "-p", help="Proxy URL to use (e.g., http://127.0.0.1:8080)"
        )
        parser.add_argument(
            "-s", "--https", action="store_true", help="Use HTTPS. (only used with -f)"
        )


# endregion
