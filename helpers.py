from colorama import Fore, Style


class Print:
    @staticmethod
    def info(msg: str):
        print(Fore.BLUE + "[i] " + Style.RESET_ALL + msg)

    @staticmethod
    def success(msg: str):
        print(Fore.GREEN +  "[i] " + Style.RESET_ALL + msg)

    @staticmethod
    def error(msg: str):
        print(Fore.RED +  "[-] " + Style.RESET_ALL + msg)

