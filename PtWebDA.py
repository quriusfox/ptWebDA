import argparse
import urllib3

from modules import RateLimitTest, HeadersTest, CSPTest, CookieTest, Log

urllib3.disable_warnings()

MODULES = {
    "ratelimit": RateLimitTest,
    "headers": HeadersTest,
    "csp": CSPTest,
    "cookies": CookieTest,
}

# MODULES = {
#     "ratelimit": RateLimitTest,
# }


def main() -> None:

    parser = argparse.ArgumentParser(
        description="PtWebDA dynamic analysis web assessment toolkit", add_help=True
    )

    parser.add_argument(
        "-j", "--json", action="store_true", help="Use Penterep JSON output format."
    )

    # Subparser for every application module
    subparsers = parser.add_subparsers(required=True, dest="module")

    for module in MODULES.values():
        module.add_subparser(subparsers)  # type: ignore

    # RateLimitTest.add_subparser(subparsers)

    # print(subparsers)
    args = parser.parse_args()

    Log.banner(args.json)

    https = False

    if args.https:
        https = True

    if args.module == "headers":
        test_headers = HeadersTest(args.url, args.file, args.proxy, https)
        test_headers.run()
    elif args.module == "ratelimit":
        test = RateLimitTest(
            args.url,
            args.file,
            args.proxy,
            https,
            num_threads=int(args.threads),
            total_requests=int(args.num_requests),
        )
        test.run()
    elif args.module == "csp":
        test_csp = CSPTest(args.url, args.file, args.proxy, https)
        test_csp.run()
    elif args.module == "cookies":
        test_cookies = CookieTest(args.url, args.file, args.proxy, https)
        test_cookies.run()
    elif args.module == "all":
        test_headers = HeadersTest(args.url, args.file, args.proxy, https)
        test_headers.run()
        test_ratelimit = RateLimitTest(args.url, args.file, args.proxy, https)
        test_ratelimit.run()
        test_csp = CSPTest(args.url, args.file, args.proxy, https)
        test_csp.run()
        test_cookies = CookieTest(args.url, args.file, args.proxy, https)
        test_cookies.run()
    else:
        parser.error("Invalid test type")


if __name__ == "__main__":
    main()
