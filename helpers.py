from colorama import Fore, Style


class Log:
    @staticmethod
    def progress(msg: str):
        print(Fore.YELLOW + "\n[*] " + Style.RESET_ALL + msg)

    @staticmethod
    def info(msg: str):
        print(Fore.BLUE + "[i] " + Style.RESET_ALL + msg)

    @staticmethod
    def success(msg: str):
        print(Fore.GREEN + "[+] " + Style.RESET_ALL + msg)

    @staticmethod
    def error(msg: str):
        print(Fore.RED + "[-] " + Style.RESET_ALL + msg)

    @staticmethod
    def warning(msg: str):
        print(Fore.YELLOW + "[!] " + Style.RESET_ALL + msg)

    @staticmethod
    def banner():
        banner = """

 __          __  _     _____
 \\ \\        / / | |   |  __ \\   /\\
  \\ \\  /\\  / /__| |__ | |  | | /  \\
   \\ \\/  \\/ / _ \\ '_ \\| |  | |/ /\\ \\
    \\  /\\  /  __/ |_) | |__| / ____ \\
     \\/  \\/ \\___|_.__/|_____/_/    \\_\\



"""
        print(banner)
