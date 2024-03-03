import argparse

from tests.ratelimit import RateLimitTest
from tests.headers import HeadersTest
from tests.csp import CSPTest
from tests.cookies import CookieTest
from helpers import Print


def main() -> int:
    Print.banner()

    parser = argparse.ArgumentParser(description="Check HTTP headers for a given URL.")
    parser.add_argument("test_type", help="Type of test to perform")
    parser.add_argument("url", help="URL to check headers for")

    args = parser.parse_args()

    if args.test_type == "headers":
        test_headers: HeadersTest = HeadersTest(args.url)
        test_headers.run_test()
    elif args.test_type == "ratelimit":
        test: RateLimitTest = RateLimitTest(args.url)
        results, avg_rps = test.run_test()

        # Calculate and print the final average response time
        average_response_time = (
            sum(response_time_ms for _, response_time_ms in results) / test.total_requests
        )
        print(f"\nAverage RPS = {avg_rps:.2f}")
        print(f"\nFinal Average Response Time = {average_response_time:.2f} ms")
    elif args.test_type == "csp":
        test_csp: CSPTest = CSPTest(args.url)
        test_csp.run_test()
    elif args.test_type == "cookies":
        test_cookies = CookieTest(args.url)
        test_cookies.run_test()
    elif args.test_type == "all":
        test_headers: HeadersTest = HeadersTest(args.url)
        test_headers.run_test()

        test: RateLimitTest = RateLimitTest(args.url)
        results, avg_rps = test.run_test()

        # Calculate and print the final average response time
        average_response_time = (
            sum(response_time_ms for _, response_time_ms in results) / test.total_requests
        )
        print(f"\nAverage RPS = {avg_rps:.2f}")
        print(f"\nFinal Average Response Time = {average_response_time:.2f} ms")
    else:
        print("[x] Invalid test type")
        help(main)

    return 0


if __name__ == "__main__":
    main()
