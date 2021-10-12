from datetime import datetime


verbose = False

# Some colors
RESET = "\x1b[39m"
CYAN = "\x1b[36m"
RED = "\x1b[36m"
LIGHTRED = "\x1b[91m"
YELLOW = "\x1b[33m"
GREEN = "\x1b[32m"
MAGENTA = "\x1b[35m"


class ModeNotFound(Exception):
    """
    Raises when the mode is not found
    """


def init(v=False):
    global verbose
    if v:
        verbose = v


def print_banner(banner):
    print(f"{GREEN}{banner}{RESET}")


def logging_console(string: str, mode: str, end="\n"):
    """
    mode: could be CRITICAL, WARNING, VERBOSE or INFO
    """
    input_string = False
    last_string = ""
    if mode == "CRITICAL":
        last_string += f"{CYAN}[{RED}!!{CYAN}]{RESET} "
    elif mode == "WARNING":
        last_string += f"{CYAN}[{LIGHTRED}!{CYAN}]{RESET} "
    elif mode == "VERBOSE":
        last_string += f"{CYAN}[{YELLOW}*{CYAN}]{RESET} "
    elif mode == "POSITIVE":
        last_string += f"{CYAN}[{GREEN}+{CYAN}]{RESET} "
    elif mode == "NEGATIVE":
        last_string += f"{CYAN}[{RED}-{CYAN}]{RESET} "
    elif mode == "INFO":
        if verbose:
            last_string += f"{CYAN}[{CYAN}i{CYAN}]{RESET} "
        else:
            return
    elif mode == "QUESTION":
        last_string += f"{CYAN}[{MAGENTA}?{CYAN}]{RESET} "
        input_string = True
    else:
        raise ModeNotFound(
            f"mode {mode} not found. Available: CRITICAL (!!), WARNING (!), VERBOSE (*) and INFO (i)")

    last_string += string

    if verbose:
        last_string = datetime.now().strftime(
            f"{CYAN}[%H:%M:%S]")+" "+last_string

    if input_string:
        print(last_string, end=end)
        user_input = input("")
        return user_input

    print(last_string, end=end)


def logging_file():
    return


def reset_bin():
    answer = ""
    while not answer.startswith("y"):
        answer = logging_console("Reset binary (Y/n/q): ", "QUESTION").lower()
        if answer == "q":
            logging_console("Exiting program by user action", "WARNING")
            exit(0)
