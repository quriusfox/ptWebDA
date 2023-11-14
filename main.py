import argparse

from tests import RateLimitTest, HeadersTest


def main() -> int:
    parser = argparse.ArgumentParser(description="Check HTTP headers for a given URL.")
    parser.add_argument("test_type", help="Type of test to perform")
    parser.add_argument("url", help="URL to check headers for")

    args = parser.parse_args()

    headers_to_check = [
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "strict-transport-security",
        "permissions-policy"
    ]

    headers_to_check_2 = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version"
    ]

    print(f"[*] Checking URL: {args.url}\n")

    if args.test_type == "headers":
        test_missing: HeadersTest = HeadersTest(args.url, headers_to_check, True)
        test_present: HeadersTest = HeadersTest(args.url, headers_to_check_2, False)
        test_missing.run_test()
        test_present.run_test()
    elif args.test_type == "ratelimit":
        total_requests = 1000

        test: RateLimitTest = RateLimitTest(args.url)
        results, avg_rps = test.run_test(10, total_requests)

        # Calculate and print the final average response time
        average_response_time = sum(response_time_ms for _, response_time_ms in results) / total_requests
        print(f"\nAverage RPS = {avg_rps:.2f}")
        print(f"\nFinal Average Response Time = {average_response_time:.2f} ms")
    else:
        print("[x] Invalid test type")
        help(main)

    return 0


if __name__ == "__main__":
    main()
