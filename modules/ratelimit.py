import sys
import time
import signal
import requests
import concurrent.futures

from threading import Event
from typing import NamedTuple

from .helpers import Log
from .http import HTTPRequest, HTTPRequestParser

RESPONSE_STATUS = {429: "HTTP 429 Too Many Requests", 509: "http 509 Bandwidth Limit Exceeded"}


class Response(NamedTuple):
    status_code: int
    response_time: float


class RateLimitResult(NamedTuple):
    rate_limited: bool
    request_threshold: int | None


class RateLimitTest:
    def __init__(
        self,
        target: str | None,
        request_file_path: str | None = None,
        https: bool = True,
        num_threads: int = 20,
        total_requests: int = 10000,
    ) -> None:
        # Values from constructor
        self.target = target
        self.num_threads: int = num_threads
        self.total_requests: int = total_requests

        # Values for preparing a requests.Request() object
        self.prepared_request = requests.Request()

        if self.target is None:
            if request_file_path:
                parser = HTTPRequestParser(request_file_path, https)
                http_request: HTTPRequest = parser.parse()

                url = (
                    "https://" + http_request.host + http_request.path
                    if http_request.https
                    else "http://" + http_request.host + http_request.path
                )

                self.prepared_request = requests.Request(
                    http_request.method, url, data=http_request.data, cookies=http_request.cookies
                )
        else:
            self.prepared_request = requests.Request("GET", self.target)

        # Values for evaluation of rate limiting
        self.failed_req: int = 0
        self.success_req = 0

        # Values for progress display in terminal
        self.start_time: float = time.time()
        self.elapsed_time: float = 0
        self.avg_rps: float = 0
        self.display_interval: float = 0.1

        # Thread handling
        self.futures = []
        self.exit_flag: Event = Event()
        signal.signal(signal.SIGINT, self.signal_handler)  # type: ignore

        # Final results
        self.results: list[Response] = []

    def run(self) -> None:
        """
        Main function for the current test.
        """
        Log.info(f"Test info:{self.test_info()}")
        Log.progress("Testing rate limit")

        result: RateLimitResult = self.test()

        if result.rate_limited and result.request_threshold is not None:
            self.evaluate(result.request_threshold)
        else:
            Log.success("Test finished successfully. No rate limit detected!")

    def test_info(self) -> str:
        """
        Provides basic information about current test's setup parameters.

        Returns:
            str: Formatted string containing test information, ready to print to console.
        """
        info = ""
        info += f"\n\tTest name:       : RateLimitTest"
        info += f"\n\tTarget:          : {self.target if self.target is not None else self.prepared_request.url}"
        info += f"\n\tThreads          : {self.num_threads}"
        info += f"\n\tTotal requests   : {self.total_requests}"
        info += f"\n\tDisplay interval : {self.display_interval}\n"

        return info

    def test(self) -> RateLimitResult:
        """
        Function sends requests to the endpoint specified during the test initialization. Function
        spawns a set amount of threads and sents a set amount of requests to the endpoint.

        Returns:
            RateLimitResult: A structure indicating whether rate limit was hit and how many requests
            it took to trigger the rate limit.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            self.futures = [executor.submit(self.make_request) for _ in range(self.total_requests)]

            for future in concurrent.futures.as_completed(self.futures):
                if self.success_req % (self.num_threads * self.display_interval) == 0:
                    self.elapsed_time = time.time() - self.start_time
                    self.display_rps()

                result = future.result()

                if result is None:
                    continue

                if self.failed_req > self.success_req:
                    for future in self.futures:
                        future.cancel()

                    return RateLimitResult(True, self.success_req)

                self.results.append(result)

            concurrent.futures.wait(self.futures)

        print(" " * 200, end="\r")

        return RateLimitResult(False, None)

    def make_request(self, path: str | None = None) -> Response | None:
        """
        Function to make a single HTTP request and measure response time

        Args:
            path (str | None, optional): A path on the web server. Defaults to None.

        Returns:
            Response | None: A structure representing HTTP status code and response time.
        """
        if self.success_req % (self.num_threads * self.display_interval) == 0:
            self.elapsed_time = time.time() - self.start_time
            self.display_rps()

        try:
            start_time = time.time()

            # Send the final prepared request in the constructor
            response = requests.Session().send(self.prepared_request.prepare())

            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            status_code: int = response.status_code

            if status_code == 509 or status_code == 429:
                self.failed_req += 1
            else:
                self.success_req += 1
            return Response(status_code, response_time)
        except requests.exceptions.RequestException:
            self.failed_req += 1
            return None

    def display_rps(self) -> None:
        """
        Function to display requests per second.

        Args:
            success_req (int): Number of requests already sent during the execution of the test()
            function.
        """
        try:
            rps: float = self.success_req / self.elapsed_time

            progress = self.success_req / self.total_requests
            bar_length = 20
            block = int(round(bar_length * progress))
            progress_bar = "[" + "=" * block + ">" + "-" * (bar_length - block) + "]"

            print(
                f"\rRequests per second: {rps:.2f}. Total requests: {(self.success_req + self.failed_req):.2f}. Failed requests: {self.failed_req:.2f} Progress: {progress_bar} {progress*100:.2f}%",
                end="",
                flush=True,
            )
        except:
            pass

    def evaluate(self, success_req: int) -> None:
        """
        Prints the information about the test's results.

        Args:
            success_req (int): Number of requests sent during the execution of the test() function.
        """
        print(" " * 200, end="\r")

        Log.error(f"Too many failed requests ({self.failed_req} / {success_req + self.failed_req})")
        Log.error("Basic heuristics suggests that the web server has rate limit configured")
        Log.info(f"Approximate threshold: {success_req} requests")
        Log.info(f"Elapsed time: {self.elapsed_time:.2f}")

        sum429 = 0
        sum509 = 0

        for result in self.results:
            if result.status_code == 429:
                sum429 += 1
            elif result.status_code == 509:
                sum509 += 1

        if sum429 != 0:
            Log.info(f"Requests terminated with '{RESPONSE_STATUS[429]}' = {sum429}")
        if sum509 != 0:
            Log.info(f"Requests terminated with '{RESPONSE_STATUS[509]}' = {sum509}")
        if self.failed_req - sum509 - sum509 > 0:
            Log.info(
                f"Requests terminated by connection error = {self.failed_req - sum429 - sum509}"
            )

    def signal_handler(self, sig, frame):  # type: ignore
        Log.error("Ctrl + C pressed. Exiting...")

        self.exit_flag.set()

        for future in self.futures:
            future.cancel()

        sys.exit(0)
