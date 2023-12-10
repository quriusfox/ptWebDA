import sys
import time
import signal
import requests

from threading import Event
from concurrent.futures import ThreadPoolExecutor, as_completed, wait

from helpers import Print, Structures


class RateLimitTest():
    def __init__(self, target: str, total_requests: int = 500, num_threads: int = 10):
        self.target           : str              = target
        self.exit_flag        : Event            = Event()
        self.futures          : list             = []
        self.results          : list             = []  # Create an empty list to store results
        self.avg_rps          : float            = 0
        self.failed_req       : int              = 0
        self.total_requests   : int              = total_requests
        self.num_threads      : int              = num_threads
        self.display_interval : int              = 0.1

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
        time.sleep(1)
        try:
            start_time = time.time()
            response = requests.get(self.target)
            response.raise_for_status()
            end_time = time.time()

            if response.status_code == 509 or response.status_code == 429:
                self.failed_req += 1
                return request_id, Structures.ERROR_HTTP_RESP_RATE_LIMIT

            # Calculate the response time in milliseconds
            response_time_ms = (end_time - start_time) * 1000

            return request_id, response_time_ms
        except requests.exceptions.RequestException as e:
            self.failed_req += 1
            return request_id, Structures.ERROR_TARGET_KILLED_CONNECTION  # Mark the request as failed

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

    def print_result(self, request_count, reason) -> None:
        print(" " * 200, end="\r")
        Print.error(f"Too many failed requests ({self.failed_req } / {request_count}).\n\tReason: {reason}\n\tApproximate threshold: {request_count - self.failed_req} requests")
        Print.error("Basic heuristics suggests that the web server has rate limit configured.")

    def run_test(self) -> [list, float]:
        """
        #TODO
        """

        Print.progress("Testing rate limit")
        self.test_info()

        # Create a ThreadPoolExecutor to manage the threads
        with ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            Print.info("Initializing the threads...")
            self.futures = [executor.submit(self.make_request, i) for i in range(self.total_requests)]
            Print.info("Test running!")
            
            start_time = time.time()
            request_count = 0

            for future in as_completed(self.futures):
                request_count += 1

                if request_count % (self.num_threads * self.display_interval) == 0:
                    elapsed_time = time.time() - start_time
                    self.display_rps(request_count, elapsed_time)

                # Collect the result of each completed request
                result = future.result()

                # Grab error reason
                err = result[1]
                reason = ""

                if err == -1:
                    reason = "ERROR_TARGET_KILLED_CONNECTION"
                if err == -2:
                    reason = "ERROR_HTTP_RESP_RATE_LIMIT"
                
                if self.failed_req  > (request_count - self.failed_req ):
                    self.print_result(request_count, reason)

                    for future in self.futures:
                        future.cancel()

                    return self.results, self.avg_rps

                self.results.append(result)

            self.avg_rps = self.total_requests / elapsed_time
        
            # Wait for all requests to complete
            wait(self.futures)
        
        print(" " * 200, end="\r")
        Print.success("Test finished successfully. No rate limit detected!")

        return self.results, self.avg_rps

    def signal_handler(self, sig, frame):
        Print.error("Ctrl + C pressed. Exiting...")

        # Set the exit flag to signal the tasks to stop
        self.exit_flag.set()

        # Cancel any pending tasks
        for future in self.futures:
            future.cancel()

        sys.exit(0)
