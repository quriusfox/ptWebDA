import re
import argparse
import requests

from typing import NamedTuple
from .utils.helpers import Log
from .basemodule import BaseModule

# region Constants
PT_VULN_CODES: dict[str, str] = {
    "httponly": "PTV-WEB-COOKIENOTHTTPONLY",
    "secure": "PTV-WEB-COOKIENOTSECURE",
    "samesite": "PTV-WEB-COOKIEWITHOUTSAMESITE",
    "samesite-none": "PTV-WEB-COOKIESAMESITENONE",
}


# endregion


# region Structures
class SameSiteAttr(NamedTuple):
    present: bool
    value: str | None


class Cookie(NamedTuple):
    name: str
    secure: bool
    http_only: bool
    same_site: SameSiteAttr
    path: str | None
    domain: str | None
    dangerous: bool


class CookieResult(NamedTuple):
    cookies: list[Cookie] | None


# endregion


# region Main module class
class CookieTest(BaseModule[CookieResult]):
    """
    This class represents the Cookie module. This module evaluates security configuration
    of cookies returned by the web server in the Set-Cookie header. The module parses cookies in
    HTTP headers and evaluates their configuration. Module's main goal is to identify cookies
    which contain such a configuration that would allow a penetration tester to perform attacks
    such as CSRF, exfiltration of authentication cookies (if XSS is present of the website)
    and similar.

    Args:
        BaseModule (_type_): This class is a child class to the BaseModule class. The test returns
        a structure of type "CookieResult".
    """

    def __init__(
        self,
        target: str | None,
        request_file_path: str | None,
        proxy: str | None,
        https: bool = True,
    ) -> None:
        """
        Constructor for the Cookeis module, mainly consisting of the target's initial setup.

        Args:
            target (str | None): URL of the target e.g. https://www.example.com/login
            request_file_path (str | None, optional): Path to a file with HTTP request exported
            e.g. from Burp Suite. Defaults to None as the primary method is "target".
            https (bool, optional): Indication of whether the request from the file is supposed to
            be sent via HTTPS. Defaults to True.
        """
        super().__init__(target, request_file_path, proxy, https)

        # Results
        self.results: CookieResult | None = None

    def run(self) -> bool:
        self.print_info()
        Log.progress("Running module")
        self.results = self.test()

        if self.results is None:
            return False

        return True

    def print_info(self):
        Log.progress(f"Test info:\n")
        Log.print("Test name : CookiesTest")
        Log.print(
            f"Target:   : {self.target if self.target is not None else self.prepared_request.url}"
        )
        Log.print(f"HTTPS     : {self.https}")
        Log.print(f"Proxies   : {self.proxies}\n")

    def test(self) -> CookieResult | None:
        all_cookies: list[Cookie] | None = None

        try:
            # Send the final prepared request in the constructor
            response: requests.Response = requests.Session().send(
                self.prepared_request.prepare(), proxies=self.proxies, verify=self.verify
            )

            # Save request and response data for the PTVuln stucture
            self.save_request_text(response.request)
            self.save_response_text(response)

            all_cookies = self._parse_cookies(response)
        except requests.exceptions.RequestException as e:
            Log.error(f"Error occurred: {e}")
            return None

        return CookieResult(all_cookies)

    def print_results(self) -> None:
        """
        Function prints the module's output. This does not have any impact on the Penterep
        integration. This function solely prints output to the terminal for the penetration tester.
        """
        if self.results is None:
            return None

        if self.results.cookies is None:
            return None

        Log.progress(f"Checking cookies returned from the server:")
        for cookie in self.results.cookies:
            Log.success(f"Found cookie: {cookie.name}")

            if not cookie.secure:
                Log.error(f"Cookie '{cookie.name}' does not have the secure flag set!")

            if not cookie.http_only:
                Log.error(f"Cookie '{cookie.name}' is not HttpOnly!")

            if not cookie.same_site.present:
                Log.error(f"Cookie '{cookie.name}' does not have SameSite attribute set")
            else:
                if cookie.same_site.value == "strict":
                    Log.info(
                        f"Cookie '{cookie.name}' has SameSite attribute set to: '{cookie.same_site.value}'"
                    )
                else:
                    Log.error(
                        f"Cookie '{cookie.name}' has SameSite attribute set to: '{cookie.same_site.value}'"
                    )

            # Log.print("")

    def json(self) -> str | None:
        """
        Function iterates over the module's results and serializes them into
        Penterep JSON structures.

        Returns:
            str | None: String representing the modules JSON output
        """
        if self.results is None:
            return None

        if self.results.cookies is None:
            return None

        for cookie in self.results.cookies:
            if not cookie.secure:
                self.ptjsonlib.add_vulnerability(
                    PT_VULN_CODES["secure"], self.request_text.decode(), self.response_text.decode()
                )

            if not cookie.http_only:
                self.ptjsonlib.add_vulnerability(
                    PT_VULN_CODES["httponly"],
                    self.request_text.decode(),
                    self.response_text.decode(),
                )

            if not cookie.same_site.present:
                self.ptjsonlib.add_vulnerability(
                    PT_VULN_CODES["samesite"],
                    self.request_text.decode(),
                    self.response_text.decode(),
                )
            else:
                if cookie.same_site.value is None:
                    continue

                if cookie.same_site.value.lower() == "none":
                    self.ptjsonlib.add_vulnerability(
                        PT_VULN_CODES["samesite-none"],
                        self.request_text.decode(),
                        self.response_text.decode(),
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

    def _parse_cookies(self, response: requests.Response) -> list[Cookie] | None:
        """
        Analyzes security attributes of HTTP cookies based on the HTTP response.

        Args:
            response (requests.Response): HTTP response object

        Returns:
            list[Cookie]: A dictionary containing security attributes of cookies
        """
        all_cookies: list[Cookie] = []

        name = ""
        secure = False
        http_only = False
        same_site = False
        same_site_value = ""
        path = ""
        domain = ""
        dangerous = False

        # Check if the response has 'Set-Cookie' header
        if "Set-Cookie" in response.headers:
            cookies = re.split(r", (?=\w+=)", response.headers["Set-Cookie"])

            for cookie in cookies:
                attribs = cookie.split("; ")
                attribs = [attr.lower() for attr in attribs]
                name = attribs[0].split("=")[0].strip()

                # Check for secure flag
                if "secure" in attribs:
                    secure = True
                else:
                    dangerous = True

                # Check for HttpOnly flag
                if "httponly" in attribs:
                    http_only = True
                else:
                    dangerous = True

                # Check for SameSite attribute
                for attr in attribs:
                    if "samesite" in attr:
                        same_site = True
                        same_site_value = attr.split("=")[1].strip()
                    else:
                        dangerous = True

                all_cookies.append(
                    Cookie(
                        name,
                        secure,
                        http_only,
                        SameSiteAttr(same_site, same_site_value),
                        path,
                        domain,
                        dangerous,
                    )
                )
        else:
            Log.info("HTTP response did not set any cookies!")
            return None

        return all_cookies


# endregion
