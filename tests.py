import sys
import time
import signal
import requests
import threading
import concurrent.futures

from helpers import Print

ERROR_TARGET_KILLED_CONNECTION = -1
ERROR_HTTP_RESP_RATE_LIMIT = -2


class RateLimitTest():
    def __init__(self, target: str, total_requests: int = 500, num_threads: int = 10):
        self.target     : str              = target
        self.exit_flag  : threading.Event  = threading.Event()
        self.futures    : list             = []
        self.results    : list             = []  # Create an empty list to store results
        self.avg_rps    : float            = 0.0
        self.failed_req : int              = 0

        # Configs
        self.total_requests = total_requests
        self.num_threads = num_threads
        self.display_interval: int = 0.1

        signal.signal(signal.SIGINT, self.signal_handler)
    

    def test_info(self):
        Print.info(f"Test info:\n")
        print("\tTest name        : RateLimitTest")
        print(f"\tTarget:          : {self.target}")
        print(f"\tThreads          : {self.num_threads}")
        print(f"\tTotal requests   : {self.total_requests}")
        print(f"\tDisplay interval : {self.display_interval}\n")


    def make_request(self, request_id) -> [int, float]:
        """
        Function to make a single HTTP request and measure response time
        """

        try:
            start_time = time.time()
            response = requests.get(self.target)
            response.raise_for_status()
            end_time = time.time()

            if response.status_code == 509:
                self.failed_req += 1
                return request_id, ERROR_HTTP_RESP_RATE_LIMIT

            # Calculate the response time in milliseconds
            response_time_ms = (end_time - start_time) * 1000

            return request_id, response_time_ms
        except requests.exceptions.RequestException as e:
            self.failed_req += 1
            return request_id, ERROR_TARGET_KILLED_CONNECTION  # Mark the request as failed


    def display_rps(self, request_count: int, elapsed_time: float):
        """
        Function to display requests per second
        """

        rps: float = request_count / elapsed_time
        

        progress = request_count / self.total_requests
        bar_length = 40
        block = int(round(bar_length * progress))
        progress_bar = "[" + "=" * block + ">" + "-" * (bar_length - block) + "]"

        print(f"\rRequests per second: {rps:.2f}. Failed requests: {self.failed_req:.2f} Progress: {progress_bar} {progress*100:.2f}%", end="", flush=True)
        # print(f"\n{progress_bar} {progress*100:.2f}%", end="", flush=True)


    def run_test(self) -> [list, float]:
        """
        #TODO
        """

        Print.progress("Testing rate limit")
        self.test_info()

        # Create a ThreadPoolExecutor to manage the threads
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            Print.info("Initializing the threads...")
            self.futures = [executor.submit(self.make_request, i) for i in range(self.total_requests)]

            start_time = time.time()
            request_count = 0

            failed_count = 0

            for future in concurrent.futures.as_completed(self.futures):
                request_count += 1

                if request_count % (self.num_threads * self.display_interval) == 0:
                    elapsed_time = time.time() - start_time
                    self.display_rps(request_count, elapsed_time)

                # Collect the result of each completed request
                result = future.result()

                err = result[1]
                reason = ""

                if err == -1:
                    failed_count += 1
                    reason = "ERROR_TARGET_KILLED_CONNECTION"
                if err == -2:
                    failed_count += 1
                    reason = "ERROR_HTTP_RESP_RATE_LIMIT"

                if failed_count > self.total_requests / 10:
                    print(" " * 200, end="\r")
                    Print.error(f"Too many failed requests ({failed_count} / {request_count}).\n\tReason: {reason}\n\tApproximate threshold: {request_count - failed_count} requests")
                    Print.error("Basic heuristics suggests that the web server has rate limit configured.")

                    for future in self.futures:
                        future.cancel()

                    return self.results, self.avg_rps

                self.results.append(result)

            self.avg_rps = self.total_requests / elapsed_time
        
            # Wait for all requests to complete
            concurrent.futures.wait(self.futures)
        
        print(" " * 200, end="\r")
        Print.success("Test finished successfully. No rate limit detected!")

        return self.results, self.avg_rps


    def signal_handler(self, sig, frame):
        Print.error("Ctrl + C pressed. Exiting...")

        # sys.exit(0)
        
        # Set the exit flag to signal the tasks to stop
        self.exit_flag.set()

        # Cancel any pending tasks
        for future in self.futures:
            future.cancel()

        sys.exit(0)


class HeadersTest():
    def __init__(self, target: str):
        self.target          : str  = target
        self.info_headers    : list = [
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version"
        ]
        self.missing_headers : list = [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "strict-transport-security",
            "permissions-policy"
        ]


    def test_info(self):
        Print.info(f"Test info:\n")
        print("\tTest name : HeadersTest")
        print(f"\tTarget    : {self.target}\n")


    def run_test(self):
        Print.progress("Testing missing headers:")
        self.test_info()

        try:
            r: requests.Response = requests.get(self.target)

            lowercase_headers: dict = {}
            
            # Convert response headers to lowercase
            for key, value in r.headers.items():
                lowercase_headers[key.lower()] = value

            Print.info("Missing headers:")
            for header in self.missing_headers:
                if header not in lowercase_headers:
                    print(f"\t{header}")    
        
            Print.info("Headers potentialy leaking information:")
            
            for header in self.info_headers:
                if header in lowercase_headers:
                    print(f"\t{header}: {lowercase_headers[header]}")

            Print.success("Test finished successfully")

        except requests.exceptions.RequestException as e:
            Print.error(f"Error occurred: {e}")

