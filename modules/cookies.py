import re
import requests

from typing import NamedTuple

from .helpers import Log
from .http import HTTPRequest, HTTPRequestParser


class Cookie(NamedTuple):
    name: str
    secure: bool
    http_only: bool
    same_site: str | None
    path: str | None
    domain: str | None


class CookieTest:
    def __init__(
        self, target: str | None, request_file_path: str | None = None, https: bool = True
    ) -> None:
        self.target = target
        self.http_request: HTTPRequest | None = None

        if self.target is None:
            if request_file_path:
                parser = HTTPRequestParser(request_file_path, https)
                self.http_request = parser.parse()

    def run(self):
        Log.progress("Analyzing cookie attributes")
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

            all_cookies = self.parse_cookies(response)

            for cookie in all_cookies:
                self.eval_cookie(cookie)

        except requests.exceptions.RequestException as e:
            Log.error(f"Error occurred: {e}")

        Log.success("Test finished successfully")

    def test_info(self):
        Log.info(f"Test info:\n")
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
                attribs = [attr.lower() for attr in attribs]
                name = attribs[0].split("=")[0].strip()

                # Check for secure flag
                if "secure" in attribs:
                    secure = True

                # Check for HttpOnly flag
                if "httponly" in attribs:
                    http_only = True

                # Check for SameSite attribute
                for attr in attribs:
                    if "samesite" in attr:
                        same_site = attr.split("=")[1].strip()

                all_cookies.append(Cookie(name, secure, http_only, same_site, path, domain))
        else:
            Log.info("HTTP response did not set any cookies!")

        return all_cookies

    def eval_cookie(self, cookie: Cookie) -> None:
        """
        Evaluates various security attributes of a given cookie.

        Args:
            cookie (Cookie): Cookie to evaluate
        """
        Log.info(f"Checking cookie {cookie.name}")

        if not cookie.secure:
            Log.warning(f"Cookie {cookie.name} does not have the secure flag set!")

        if not cookie.http_only:
            Log.warning(f"Cookie {cookie.name} is not HttpOnly!")

        if cookie.same_site:
            Log.warning(f"Cookie {cookie.name} has SameSite attribute set to: {cookie.same_site}")
