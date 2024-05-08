import urllib3
import argparse

from ptlibs import ptprinthelper  # type: ignore
from modules import RateLimitTest, HeadersTest, CSPTest, CookieTest, Log

urllib3.disable_warnings()

__version__ = "1.0"

MODULES = {
    "ratelimit": RateLimitTest,
    "headers": HeadersTest,
    "csp": CSPTest,
    "cookies": CookieTest,
}


class PtWebDA:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args

    def run(self):
        test: RateLimitTest | HeadersTest | CSPTest | CookieTest | None = None
        res: bool = False

        https = True

        if self.args.file is not None:
            https = False

        if self.args.https is None and self.args.file is not None:
            https = True

        # Supress console output if output is JSON
        if self.args.json:
            Log.silent = True

        if self.args.module == "headers":
            test = HeadersTest(self.args.url, self.args.file, self.args.proxy, https)
            res = test.run()
        elif self.args.module == "ratelimit":
            test = RateLimitTest(
                self.args.url,
                self.args.file,
                self.args.proxy,
                https,
                num_threads=int(self.args.threads),
                total_requests=int(self.args.num_requests),
            )
            res = test.run()
        elif self.args.module == "csp":
            test = CSPTest(self.args.url, self.args.file, self.args.proxy, https)
            res = test.run()
        elif self.args.module == "cookies":
            test = CookieTest(self.args.url, self.args.file, self.args.proxy, https)
            res = test.run()

        if test is None:
            return

        if not res:
            Log.error("Module failed to finish successfully")
            return

        # Two variants of tool's output
        if self.args.json:
            print(test.json())
        else:
            test.print_results()

        Log.success("Module finished successfully")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PtWebDA dynamic analysis web assessment toolkit", add_help=True
    )

    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}", help="print version"
    )
    parser.add_argument(
        "-j", "--json", action="store_true", help="Use Penterep JSON output format."
    )

    # Subparser for every application module
    subparsers = parser.add_subparsers(required=True, dest="module")

    for module in MODULES.values():
        module.add_subparser(subparsers)  # type: ignore

    args = parser.parse_args()

    ptprinthelper.print_banner(SCRIPTNAME, __version__, args.json)  # type: ignore

    return args


def main() -> None:
    global SCRIPTNAME
    SCRIPTNAME = "ptwebda"
    args = parse_args()

    script = PtWebDA(args)
    script.run()


if __name__ == "__main__":
    main()
