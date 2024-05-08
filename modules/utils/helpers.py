from colorama import Fore, Style
from ptlibs import ptprinthelper


class Log:
    silent: bool = False

    @staticmethod
    def progress(msg: str):
        ptprinthelper.ptprint(ptprinthelper.out_title(msg), condition=not Log.silent)

    @staticmethod
    def info(msg: str):
        ptprinthelper.ptprint(
            Fore.LIGHTBLUE_EX + "[i] " + Style.RESET_ALL + msg, condition=not Log.silent
        )

    @staticmethod
    def success(msg: str):
        ptprinthelper.ptprint(
            Fore.LIGHTGREEN_EX + "[+] " + Style.RESET_ALL + msg, condition=not Log.silent
        )

    @staticmethod
    def error(msg: str):
        ptprinthelper.ptprint(
            Fore.LIGHTRED_EX + "[!] " + Style.RESET_ALL + msg, condition=not Log.silent
        )

    @staticmethod
    def warning(msg: str):
        ptprinthelper.ptprint(
            Fore.YELLOW + "[!] " + Style.RESET_ALL + msg, condition=not Log.silent
        )

    @staticmethod
    def print(msg: str):
        ptprinthelper.ptprint(f"\t{msg}", condition=not Log.silent)
