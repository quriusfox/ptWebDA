import argparse

from modules import RateLimitTest
from modules import HeadersTest
from modules import CSPTest
from modules import CookieTest

from helpers import Log


def main() -> None:
    Log.banner()

    parser = argparse.ArgumentParser(description="Check HTTP headers for a given URL.")
    parser.add_argument("test_type", help="Type of test to perform")
    parser.add_argument("url", help="URL to check headers for")

    args = parser.parse_args()

    if args.test_type == "headers":
        test_headers: HeadersTest = HeadersTest(args.url)
        test_headers.run()
    elif args.test_type == "ratelimit":
        test: RateLimitTest = RateLimitTest(args.url)
        test.run()
    elif args.test_type == "csp":
        test_csp: CSPTest = CSPTest(args.url)
        test_csp.run()
    elif args.test_type == "cookies":
        test_cookies = CookieTest(args.url)
        test_cookies.run()
    elif args.test_type == "all":
        pass
    else:
        print("[x] Invalid test type")
        help(main)


if __name__ == "__main__":
    main()
