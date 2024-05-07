import argparse
import requests

from requests.structures import CaseInsensitiveDict
from bs4 import BeautifulSoup
from typing import NamedTuple

from .utils.helpers import Log
from .basemodule import BaseModule, PTVuln

# region Constants
CSP_HEADERS: list[str] = ["content-security-policy", "x-content-security-policy", "x-webkit-csp"]
# endregion


# region Structures
class Html:
    """
    This class represents a content of a web page that is a result of a HTTP request and later used
    for HTML arsing with BeautifulSoup and analysis of a CSP configuration within HTML code.
    """

    def __init__(self, url: str, content: str) -> None:
        """
        Constructor for the Html response object.

        Args:
            url (str): URL of the web page/endpoint.
            content (str): String representation of the HTML content of the returned page (later
            parsed with BeautifulSoup)
        """
        self.url: str = url
        self.content = content
        self.soup_body = BeautifulSoup(self.content, "html.parser")


class Response(NamedTuple):
    """
    Structure representing the response to the HTML request. This structure strips the
    requests.Request object off the unnecessary data and adds the Html object for HTML code parsing.
    """

    headers: CaseInsensitiveDict[str]
    html: Html


class CSPDirective(NamedTuple):
    """
    Simple structure representing the CSP directive and a indication whether the configuration
    is considered dangerous.
    """

    name: str
    content: str | None
    dangerous: bool


class CSPResult(NamedTuple):
    """
    Structure holds lists of evaluated CSP directives from both HTTP headers and HTML source code.
    """

    csp_headers: list[CSPDirective] | None
    csp_html: list[CSPDirective] | None


# endregion


# region Main module class
class CSPTest(BaseModule[CSPResult]):
    """
    This class represents the CSP module. This module evaluates security configuration
    of Content Security Policy contained in both HTTP headers and HTML source code via
    <meta http-equiv...> tags that are returned (or not returned) by the web server. The module
    parses both HTTP headers and HTML reponse body and searches for the CSP configuraton. Then, the
    analysis is performed. Module's main goal is to identify such a configuration that would allow
    a penetration tester to perform attacks such as XSS and similar.

    Args:
        BaseModule (_type_): This class is a child class to the BaseModule class. The test returns
        a structure of type "CSPResult".
    """

    def __init__(
        self,
        target: str | None,
        request_file_path: str | None,
        proxy: str | None,
        https: bool = True,
    ) -> None:
        """
        Constructor for the CSP module, mainly consisting of the target's initial setup.

        Args:
            target (str | None): URL of the target e.g. https://www.example.com/login
            request_file_path (str | None, optional): Path to a file with HTTP request exported
            e.g. from Burp Suite. Defaults to None as the primary method is "target".
            https (bool, optional): Indication of whether the request from the file is supposed to
            be sent via HTTPS. Defaults to True.
        """
        super().__init__(target, request_file_path, proxy, https)

        # Penterep compatibility
        self.request_text: bytes = b""
        self.response_text: bytes = b""

        # Results
        self.results: CSPResult | None = None

    def run(self):
        self.print_info()
        self.results = self.test()
        self.evaluate()
        self.print_results()

    def print_info(self):
        """
        Provides basic information about current test's setup parameters.
        """
        Log.progress(f"Test info:\n")
        print("\tTest name : CSPTest")
        print(f"\tTarget    : {self.target}\n")

    def test(self) -> CSPResult:
        csp_headers: list[CSPDirective] | None = None
        csp_html: list[CSPDirective] | None = None

        try:
            # Send the final prepared request in the constructor
            response: requests.Response = requests.Session().send(
                self.prepared_request.prepare(), proxies=self.proxies, verify=self.verify
            )

            # Save request and response data for the PTVuln stucture
            self.save_request_text(response.request)
            self.save_response_text(response)

            r = Response(response.headers, Html(response.url, response.text))

            csp_headers = self.__check_csp_headers(r)
            csp_html = self.__check_csp_html(r)
        except requests.exceptions.RequestException as e:
            Log.error(f"Error occurred: {e}")

        return CSPResult(csp_headers, csp_html)

    def evaluate(self) -> None:
        """
        Function takes the data from CSPResults structure and transforms it to Penterep
        compatible PTVuln structure.
        """
        if self.results is None:
            return None

        res: list[PTVuln] = [PTVuln("PTV-WEB-CSPMISCONFIG", self.request_text, self.response_text)]

        self.evaluation = res

    def print_results(self) -> None:
        """
        Function prints the module's output. This does not have any impact on the Penterep
        integration. This function solely prints output to the terminal for the penetration tester.
        """
        if self.results is None:
            Log.error("Results cannot be printed! Value of results is None")
            return None

        if self.results.csp_headers is None and self.results.csp_html is None:
            return None

        Log.info("CSP directies:")

        for csp in self.results:
            if csp is None:
                continue

            for directive in csp:
                if directive.dangerous:
                    Log.error(f"{directive.name} {directive.content}")
                else:
                    Log.info(f"{directive.name} {directive.content}")

    def json(self) -> None:
        raise NotImplementedError

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

    def __eval_directives(self, directives: list[str]) -> list[CSPDirective]:
        eval_directives: list[CSPDirective] = []

        required_directives = {"object-src", "default-src", "base-uri"}
        present_directives = {directive.split()[0] for directive in directives}
        missing_directives = required_directives - present_directives

        # Append missing directives
        for directive_name in missing_directives:
            eval_directives.append(CSPDirective(directive_name, None, True))

        for directive in directives:
            name: str = ""
            content: str = ""

            directive = directive.lower()
            splitted = directive.split(" ", 1)
            name = splitted[0]

            if len(splitted) > 1:
                content = splitted[1]

            # Conditions for evaluation
            if "unsafe" in directive:
                eval_directives.append(CSPDirective(name, content, True))
                continue

            if name == "script-src" and "data:" in content:
                eval_directives.append(CSPDirective(name, content, True))
                continue

            if "strict-dynamic" in directive:
                eval_directives.append(CSPDirective(name, content, True))
                continue

            if "*" in directive:
                eval_directives.append(CSPDirective(name, content, True))
                continue
            else:
                eval_directives.append(CSPDirective(name, content, False))

        return eval_directives

    def __check_csp_headers(self, response: Response) -> list[CSPDirective] | None:
        directives: list[str] = []

        for key, value in response.headers.items():
            if key.lower() in CSP_HEADERS:
                directives = value.split("; ")

        if len(directives) == 0:
            Log.info("Server did not respond with any CSP headers!")
            return None

        return self.__eval_directives(directives)

    def __check_csp_html(self, response: Response) -> list[CSPDirective] | None:
        directives: list[str] = []

        for meta_http in response.html.soup_body.find_all(
            "meta", attrs={"http-equiv": True, "content": True}
        ):
            for header in CSP_HEADERS:
                if meta_http["http-equiv"].lower().strip() == header:
                    directives = meta_http["content"].split(";")

        if len(directives) == 0:
            Log.info("HTML content does not include any CSP configuration!")
            return None

        self.__eval_directives(directives)


# endregion
