import argparse
import requests

from abc import ABC, abstractmethod
from typing import NamedTuple
from .http import HTTPRequest, HTTPRequestParser


# region Structures
class PTVuln(NamedTuple):
    """
    Structure holds information that are Penterep compatible and are later serialized into JSON.
    This ensures Penterep platform compatibility.

    """

    code: str
    request: bytes
    response: bytes


# endregion


# region Main module class
class BaseModule[T](ABC):
    """
    This is the base module for all modules that are implemented in this project. Here we define
    multiple methods that are mandatory for each moodule. Their implementation relies on the given
    test and it's purpose, however, the structure should alwayls remain the same.
    """

    def __init__(
        self, target: str | None, request_file_path: str | None = None, https: bool = True
    ) -> None:
        """
        In the constructor we define all parameters that are the same among all modules.

        Args:
            target (str | None): URL of the target e.g. https://www.example.com/login
            request_file_path (str | None, optional): Path to a file with HTTP request exported
            e.g. from Burp Suite. Defaults to None as the primary method is "target".
            https (bool, optional): Indication of whether the request from the file is supposed to
            be sent via HTTPS. Defaults to True.
        """
        super().__init__()

        self.target = target

        # Values for preparing a requests.Request() object
        self.prepared_request = self.__prepare_request(request_file_path, https)

        # Penterep compatibility
        self.request_text: bytes = b""
        self.response_text: bytes = b""

        # Results
        self.results: T | None = None
        self.evaluation: list[PTVuln] | None = None

    def save_request_text(self, request: requests.PreparedRequest) -> None:
        """
        Save the request for PTVuln structure.
        """
        if request.method is None or request.url is None:
            return None

        self.request_text = (request.method + " " + request.url + " HTTP/1.1\r\n").encode()
        self.request_text += (
            "".join([f"{k}: {v}\r\n" for k, v in request.headers.items()])
        ).encode()
        self.request_text += "\r\n".encode()

    def save_response_text(self, response: requests.Response):
        """
        Save the reponse for PTVuln structure.
        """
        status_line = f"HTTP/{response.raw.version} {response.status_code} {response.reason}\r\n"
        headers = "".join([f"{k}: {v}\r\n" for k, v in response.headers.items()])

        # Combine status line and headers
        self.response_text = (status_line + headers).encode()

    def __prepare_request(self, request_file_path: str | None, https: bool) -> requests.Request:
        """
        Constructing requests.Request object parsing request file or using just target.

        Args:
            request_file_path (str | None): Path to the request file.
            https (bool): Indication on whether HTTPS should be used.

        Returns:
            requests.Request: Object representing the request that will be used throughout the test.
        """
        prepared_request = requests.Request()

        if self.target is None:
            if request_file_path:
                parser = HTTPRequestParser(request_file_path, https)
                http_request: HTTPRequest = parser.parse()

                url = (
                    "https://" + http_request.host + http_request.path
                    if http_request.https
                    else "http://" + http_request.host + http_request.path
                )

                prepared_request = requests.Request(
                    http_request.method, url, data=http_request.data, cookies=http_request.cookies
                )
        else:
            prepared_request = requests.Request("GET", self.target)
            prepared_request.headers["User-Agent"] = "Penterep Tools"

        return prepared_request

    @abstractmethod
    def run(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def print_info(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def test(self) -> T:
        raise NotImplementedError

    @abstractmethod
    def evaluate(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def print_results(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def json(self) -> None:
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def add_subparser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore
        raise NotImplementedError


# endregion
