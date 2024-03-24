import re
import inspect
import requests

from requests.structures import CaseInsensitiveDict
from bs4 import BeautifulSoup
from typing import NamedTuple

from modules.helpers import Log

CSP_HEADERS = {"content-security-policy", "x-content-security-policy", "x-webkit-csp"}


class Html:
    def __init__(self, url: str, content: str) -> None:
        self.url: str = url
        self.content = content
        self.soup_body = BeautifulSoup(self.content, "html.parser")


class Response(NamedTuple):
    headers: CaseInsensitiveDict[str]
    html: Html


class CSPDirective(NamedTuple):
    name: str
    content: str
    source: str
    dangerous: bool


class CSPTest:
    def __init__(self, target: str) -> None:
        self.target = target

        self.csp_directives: list[CSPDirective] = []

    def run(self):
        self.test_info()
        Log.progress("Analyzing CSP directives")

        self.test()

    def test_info(self):
        Log.info(f"Test info:\n")
        print("\tTest name : CSPTest")
        print(f"\tTarget    : {self.target}\n")

    def test(self):
        try:
            response: requests.Response = requests.get(self.target)

            r = Response(response.headers, Html(response.url, response.text))

            self.check_csp_headers(r)
            self.check_csp_html(r)

        except requests.exceptions.RequestException as e:
            Log.error(f"Error occurred: {e}")

        Log.success("Test finished successfully")

    def check_csp_headers(self, response: Response) -> None:
        for key, value in response.headers.items():
            if key.lower() in CSP_HEADERS:
                directives = value.split("; ")

                self.csp_directives = self.eval_directives(directives)

    def check_csp_html(self, response: Response) -> None:
        for meta_http in response.html.soup_body.find_all(
            "meta", attrs={"http-equiv": True, "content": True}
        ):
            for header in CSP_HEADERS:
                if meta_http["http-equiv"].lower().strip() == header:
                    directives = meta_http["content"].split(";")

                    self.csp_directives = self.eval_directives(directives)

    def eval_directives(self, directives: list[str]) -> list[CSPDirective]:
        eval_directives: list[CSPDirective] = []

        for directive in directives:
            directive = directive.lower()

            unsafe = "unsafe" in directive
            wildcard = "*" in directive

            # This reges should catch directives like "data:", "blob:" etc. Basically those that
            # do not define any restrictions
            too_permissive = re.findall(
                "[a-z]*:\\s|[a-z]*:\\s[a-z]*:\\s|(?!.*:[/]{2})[a-z]*:",
                directive,
            )

            splitted = directive.split(" ", 1)
            name = splitted[0]
            content = splitted[1]

            # Get name of the caller function to determine the source of the CSP directive
            caller = inspect.stack()[1].function.split("_")[2]

            if unsafe or wildcard or any(too_permissive):
                Log.warning(directive)
                eval_directives.append(CSPDirective(name, content, caller, True))
                continue
            else:
                Log.info(directive)
                eval_directives.append(CSPDirective(name, content, caller, False))

        return eval_directives
