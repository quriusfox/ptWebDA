import argparse
from modules import RateLimitTest, HeadersTest, CSPTest, CookieTest, Log


def main() -> None:
    Log.banner()

    parser = argparse.ArgumentParser(description="Check HTTP headers for a given URL.")
    parser.add_argument(
        "test_type",
        choices=["headers", "ratelimit", "csp", "cookies", "all"],
        help="Type of test to perform",
    )
    parser.add_argument("--url", help="URL to check headers for")
    parser.add_argument("--file", "-f", help="Path to the file used by the modules (optional)")

    args = parser.parse_args()

    if args.test_type == "headers":
        test_headers = HeadersTest(args.url, args.file)
        test_headers.run()
    elif args.test_type == "ratelimit":
        test = RateLimitTest(args.url, args.file)
        test.run()
    elif args.test_type == "csp":
        test_csp = CSPTest(args.url, args.file)
        test_csp.run()
    elif args.test_type == "cookies":
        test_cookies = CookieTest(args.url, args.file)
        test_cookies.run()
    elif args.test_type == "all":
        test_headers = HeadersTest(args.url, args.file)
        test_headers.run()
        test_ratelimit = RateLimitTest(args.url, args.file)
        test_ratelimit.run()
        test_csp = CSPTest(args.url, args.file)
        test_csp.run()
        test_cookies = CookieTest(args.url, args.file)
        test_cookies.run()
    else:
        parser.error("Invalid test type")


if __name__ == "__main__":
    main()
