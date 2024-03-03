import re
import requests
from helpers import Print
from typing import NamedTuple


class Cookie(NamedTuple):
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    path: str | None
    domain: str | None


class CookieTest:
    def __init__(self, target: str) -> None:
        self.target = target

    def test_info(self):
        Print.info(f"Test info:\n")
        print("\tTest name : CookeisTest")
        print(f"\tTarget    : {self.target}\n")

    def parse_cookies(self, response: requests.Response) -> list[Cookie]:
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
        same_site = ""
        path = ""
        domain = ""

        # Check if the response has 'Set-Cookie' header
        if "Set-Cookie" in response.headers:
            cookies = re.split(r", (?=\w+=)", response.headers["Set-Cookie"])

            for cookie in cookies:
                attribs = cookie.split("; ")
                name = attribs[0].split("=")[0].strip()

                # Check for secure flag
                if "secure" in attribs:
                    secure = True

                # Check for HttpOnly flag
                if "HttpOnly" in attribs:
                    http_only = True

                # Check for SameSite attribute
                for attr in attribs:
                    if "SameSite" in attr:
                        same_site = attr.split("=")[1].strip()

                all_cookies.append(Cookie(name, secure, http_only, same_site, path, domain))
        else:
            Print.info("HTTP response did not set any cookies!")

        return all_cookies

    def eval_cookie(self, cookie: Cookie) -> None:
        """
        Evaluates various security attributes of a given cookie.

        Args:
            cookie (Cookie): Cookie to evaluate
        """
        Print.info(f"Checking cookie {cookie.name}")

        if not cookie.secure:
            Print.warning(f"Cookie {cookie.name} does not have the secure flag set!")

        if not cookie.http_only:
            Print.warning(f"Cookie {cookie.name} is not HttpOnly!")

        if not cookie.same_site:
            Print.warning(f"Cookie {cookie.name} has SameSite attribute set to: {cookie.same_site}")

    def run_test(self):
        Print.progress("Analyzing cookie attributes")
        self.test_info()

        try:
            response: requests.Response = requests.get(self.target)

            all_cookies = self.parse_cookies(response)

            for cookie in all_cookies:
                self.eval_cookie(cookie)

        except requests.exceptions.RequestException as e:
            Print.error(f"Error occurred: {e}")

        Print.success("Test finished successfully")
