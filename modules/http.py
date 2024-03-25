from io import BytesIO
from typing import NamedTuple


class HTTPRequest(NamedTuple):
    method: str
    host: str
    path: str
    https: bool
    user_agent: str | None
    cookies: dict[str, str] | None
    data: str | None


class HTTPRequestParser:
    def __init__(self, request_file_path: str, https: bool) -> None:
        """
        Constructor of the HTTPRequestParser class reads bytes from a file and prepares for the manual
        parsing of the HTTP requests read from the file.

        Args:
            request_file_path (str): Path to the file with HTTP request (e.g. from BurpSuite).
            https (bool): Indication whether the request was sent via HTTPS.
        """
        # Read the bytes from the file
        with open(request_file_path, "rb") as f:
            raw_http_request = f.read()

        self.rfile = BytesIO(raw_http_request)
        self.https = https

    def parse(self) -> HTTPRequest:
        """
        Parses a HTTP request from raw bytes.

        Raises:
            ValueError: This exception is raised when mandatory fields of HTTPRequest structure are
            missing.

        Returns:
            HTTPRequest: Structure representing parsed HTTP request.
        """
        first_line = self.rfile.readline().decode("utf-8")
        method, path, _ = first_line.strip().split(" ")
        headers: dict[str, str] = self.parse_headers()

        host: str | None = headers.get("Host")
        user_agent: str | None = headers.get("User-Agent")
        cookies: dict[str, str] | None = self.parse_cookies(headers.get("Cookie"))

        if host is None:
            raise ValueError("Host header not found")

        # Read data from the request body
        content_length = int(headers.get("Content-Length", 0))
        data = None

        if content_length > 0:
            data = self.rfile.read(content_length).decode("utf-8")

        return HTTPRequest(method, host, path, self.https, user_agent, cookies, data)

    def parse_headers(self) -> dict[str, str]:
        """
        Parses HTTP headers from the raw bytes of the currently parsed HTTP request.

        Returns:
            dict[str, str]: Dictionary containing HTTP headers and their respective values.
        """
        headers: dict[str, str] = {}

        # Iterate over all lines in the HTTP request file
        while True:
            line = self.rfile.readline().decode("utf-8").strip()

            if not line:
                break

            header, value = line.split(":", 1)
            headers[header.strip()] = value.strip()

        return headers

    def parse_cookies(self, cookies: str | None) -> dict[str, str] | None:
        """
        Parses cookies from a raw line from the currently parsed HTTP request.

        Returns:
            dict[str, str]: _description_
        """
        if cookies is None:
            return None

        cookie_dict: dict[str, str] = {}

        if cookies:
            for cookie in cookies.split(";"):
                key, value = cookie.split("=")
                cookie_dict[key.strip()] = value.strip()

        return cookie_dict
