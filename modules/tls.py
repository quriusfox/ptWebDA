import ssl
import socket

from typing import NamedTuple

from .http import HTTPRequest, HTTPRequestParser
from .helpers import Log


class TLSConfig(NamedTuple):
    SSLv2: bool
    SSLv3: bool
    TLSv1: bool
    TLSv1_1: bool
    TLSv1_2: bool
    TLSv1_3: bool


class TLSTest:
    def __init__(self, target: str | None, request_file_path: str | None) -> None:
        self.hostname: str = ""
        self.port = 443

        if target is None:
            if request_file_path:
                # https param is always set to True since we are in fact testing HTTPS config
                parser = HTTPRequestParser(request_file_path, True)
                http_request: HTTPRequest = parser.parse()
                self.hostname = http_request.host
            else:
                raise ValueError("Nothing to use as target!")
        else:
            clean_target = target.split("://", 1)[1].split("/")[0]
            self.hostname = clean_target.split(":")[0]

            if ":" in clean_target:
                self.port = int(clean_target.split(":")[1])

        self.list_version_ssl_tls: dict[str, int] = {
            "SSLv2": ssl.OP_ALL
            | ssl.OP_NO_SSLv3
            | ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_NO_TLSv1_2
            | ssl.OP_NO_SSLv3,
            "SSLv3": ssl.OP_ALL
            | ssl.OP_NO_SSLv2
            | ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_NO_TLSv1_2
            | ssl.OP_NO_SSLv3,
            "TLSv1": ssl.OP_ALL
            | ssl.OP_NO_SSLv2
            | ssl.OP_NO_SSLv3
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_NO_TLSv1_2
            | ssl.OP_NO_SSLv3,
            "TLSv1_1": ssl.OP_ALL
            | ssl.OP_NO_SSLv2
            | ssl.OP_NO_SSLv3
            | ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_2
            | ssl.OP_NO_SSLv3,
            "TLSv1_2": ssl.OP_ALL
            | ssl.OP_NO_SSLv2
            | ssl.OP_NO_SSLv3
            | ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_NO_SSLv3,
            "TLSv1_3": ssl.OP_ALL
            | ssl.OP_NO_SSLv2
            | ssl.OP_NO_SSLv3
            | ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_NO_TLSv1_2,
        }

        self.result: TLSConfig | None = None

    def run(self):
        Log.info(f"Test info:{self.test_info()}")
        Log.progress("Testing TLS configuration")

        self.result = self.test()

        print(self.result)

    def test_info(self) -> str:
        """
        Provides basic information about current test's setup parameters.

        Returns:
            str: Formatted string containing test information, ready to print to console.
        """
        info = ""
        info += f"\n\tTest name:       : TLSTest"
        info += f"\n\tTarget           : {self.hostname}"
        info += f"\n\tPort             : {self.port}\n"

        return info

    def test(self) -> TLSConfig:
        results: list[bool] = []

        for cipher_name, cipher in self.list_version_ssl_tls.items():
            try:
                ip_address = socket.gethostbyname(self.hostname)
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.options = ssl.Options(cipher)

                with socket.create_connection((ip_address, self.port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as _:
                        results.append(True)
                        Log.success(
                            f"Server accepts connection using SSL/TLS version: {cipher_name}"
                        )

            except socket.gaierror:
                print(f"Error: Unable to resolve hostname '{self.hostname}'. Please check the URL.")
            except Exception:
                results.append(False)
                Log.error(f"Server refused connection using SSL/TLS version: {cipher_name}")

        return TLSConfig(*results)
