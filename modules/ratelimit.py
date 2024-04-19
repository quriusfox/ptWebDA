import sys
import time
import signal
import argparse
import requests
import concurrent.futures

from threading import Event
from typing import NamedTuple

from .helpers import Log
from .basemodule import BaseModule

# region Constants
RESPONSE_STATUS = {429: "HTTP 429 Too Many Requests", 509: "http 509 Bandwidth Limit Exceeded"}

# endregion


# region Structures
class Response(NamedTuple):
    status_code: int
    response_time: float


class RateLimitResult(NamedTuple):
    rate_limited: bool
    request_threshold: int | None


# endregion


# region Main module class
class RateLimitTest(BaseModule[RateLimitResult]):
    """
    This class represents the rate limiting module. This module tries to evaluate whether the target
    werb server performs some sort of rate limiting. The module sends a pre-defined amount of HTTP
    requests to a specified endpoint and monitors how the web server reacts to this heavier load.

    The rate limiting is detected based on the premises that the number of failed reqeusts must NOT
    surpass the number of successful reqeusts. This approach is not optimal and cannot cover complex
    cases, however, it should be efficient enought to detect rate limiting on some web forms or
    various APIs.

    If the rate limiting is detected by the module, the tester is informed about the apporximate
    threshold of how many request were sent before the server enforced rate limiting.
    """

    def __init__(
        self,
        target: str | None,
        request_file_path: str | None,
        proxy: str | None,
        https: bool = True,
        num_threads: int = 50,
        total_requests: int = 1000,
    ) -> None:
        """
        Constructor for the HTTP headers module. At first the target setup is performed. Tester can
        also specify numbr of theads to use and total number of requests that should be sent during
        the test.

        Args:
            target (str | None): _description_
            request_file_path (str | None, optional): _description_. Defaults to None.
            https (bool, optional): _description_. Defaults to True.
            num_threads (int, optional): _description_. Defaults to 20.
            total_requests (int, optional): _description_. Defaults to 10000.
        """
        super().__init__(target, request_file_path, proxy, https)

        # Values from constructor
        self.num_threads: int = num_threads
        self.total_requests = total_requests

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
        signal.signal(signal.SIGINT, self.__signal_handler)  # type: ignore

        # Final results
        self.meta_resutls: list[Response] = []
        self.result: RateLimitResult | None = None

    def run(self) -> None:
        """
        Main function for the current test.
        """
        self.print_info()
        self.result: RateLimitResult | None = self.test()
        self.print_results()

        Log.success("Test finished successfully")

    def print_info(self) -> None:
        """
        Provides basic information about current test's setup parameters.
        """
        Log.progress(f"Test info:\n")

        info = ""
        info += f"\n\tTest name:       : RateLimitTest"
        info += f"\n\tTarget:          : {self.target if self.target is not None else self.prepared_request.url}"
        info += f"\n\tThreads          : {self.num_threads}"
        info += f"\n\tTotal requests   : {self.total_requests}"
        info += f"\n\tDisplay interval : {self.display_interval}\n"

        print(info)

    def test(self) -> RateLimitResult:
        """
        Function sends requests to the endpoint specified during the test initialization. Function
        spawns a set amount of threads and sents a set amount of requests to the endpoint.

        Returns:
            RateLimitResult: A structure indicating whether rate limit was hit and how many requests
            it took to trigger the rate limit.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            self.futures = [
                executor.submit(self.__make_request) for _ in range(self.total_requests)
            ]

            for future in concurrent.futures.as_completed(self.futures):
                if self.success_req % (self.num_threads * self.display_interval) == 0:
                    self.elapsed_time = time.time() - self.start_time
                    self.__display_rps()

                result = future.result()

                if result is None:
                    continue

                if self.failed_req > self.success_req:
                    for future in self.futures:
                        future.cancel()

                    return RateLimitResult(True, self.success_req)

                self.meta_resutls.append(result)

            concurrent.futures.wait(self.futures)

        print(" " * 200, end="\r")

        return RateLimitResult(False, None)

    def evaluate(self) -> None:
        raise NotImplementedError

    def print_results(self) -> None:
        """
        Prints the information about the test's results.
        """
        print(" " * 200, end="\r")

        if self.result is None:
            return None

        if not self.result.rate_limited:
            Log.success("No rate limit detected!")
            return None

        Log.error(
            f"Too many failed requests ({self.failed_req} / {self.success_req + self.failed_req})"
        )
        Log.error("Basic heuristics suggests that the web server has rate limit configured")
        Log.info(f"Approximate threshold: {self.success_req} requests")
        Log.info(f"Elapsed time: {self.elapsed_time:.2f}")

        sum429 = 0
        sum509 = 0

        for result in self.meta_resutls:
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

    def json(self) -> None:
        raise NotImplementedError

    @staticmethod
    def add_subparser(subparsers: argparse._SubParsersAction) -> None:  # type: ignore
        raise NotImplementedError

    def __make_request(self, path: str | None = None) -> Response | None:
        """
        Function to make a single HTTP request and measure response time

        Args:
            path (str | None, optional): A path on the web server. Defaults to None.

        Returns:
            Response | None: A structure representing HTTP status code and response time.
        """
        if self.success_req % (self.num_threads * self.display_interval) == 0:
            self.elapsed_time = time.time() - self.start_time
            self.__display_rps()

        try:
            start_time = time.time()

            # Send the final prepared request in the constructor
            response = requests.Session().send(
                self.prepared_request.prepare(), proxies=self.proxies, verify=self.verify
            )

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

    def __display_rps(self) -> None:
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

    def __signal_handler(self, sig, frame):  # type: ignore
        Log.error("Ctrl + C pressed. Exiting...")

        self.exit_flag.set()

        for future in self.futures:
            future.cancel()

        sys.exit(0)


# endregion
