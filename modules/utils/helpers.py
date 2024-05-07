from colorama import Fore, Style
from ptlibs import ptprinthelper


class Log:
    @staticmethod
    def progress(msg: str):
        # print(Fore.YELLOW + "\n[*] " + Style.RESET_ALL + msg)
        ptprinthelper.ptprint(ptprinthelper.out_title(msg))

    @staticmethod
    def info(msg: str):
        ptprinthelper.ptprint(Fore.LIGHTBLUE_EX + "[i] " + Style.RESET_ALL + msg)

    @staticmethod
    def success(msg: str):
        ptprinthelper.ptprint(Fore.LIGHTGREEN_EX + "[+] " + Style.RESET_ALL + msg)

    @staticmethod
    def error(msg: str):
        ptprinthelper.ptprint(Fore.LIGHTRED_EX + "[!] " + Style.RESET_ALL + msg)

    @staticmethod
    def warning(msg: str):
        ptprinthelper.ptprint(Fore.YELLOW + "[!] " + Style.RESET_ALL + msg)

    @staticmethod
    def banner(json: bool):
        global SCRIPTNAME
        SCRIPTNAME = "ptwebda"

        ptprinthelper.print_banner(SCRIPTNAME, "0.9", json)
