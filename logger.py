import os
from datetime import datetime
import json
from typing import Union


verbose = False
output = ""
overwrite = False
IP = ""

# Some colors
RESET = "\x1b[39m"
CYAN = "\x1b[36m"
RED = "\x1b[31m"
LIGHTRED = "\x1b[91m"
YELLOW = "\x1b[33m"
GREEN = "\x1b[32m"
MAGENTA = "\x1b[35m"

# other constant variables
home_folder = os.path.expanduser("~")+"/"


class ModeNotFound(Exception):
    """
    Raises when the mode is not found
    """


def init(v: bool = False, save_output: str = "", allowed_to_overwrite: bool = False, ip: str = ""):
    global verbose, output, overwrite, IP
    verbose, output, overwrite = v, save_output, allowed_to_overwrite
    if not IP:
        IP = ip

    directory = home_folder+".BAF"

    if not os.path.isdir(directory):
        os.mkdir(directory)


def backup_logs(replace: bool = False, input_output: bool = False, data: dict = {}, log_dir: str = home_folder+f".BAF/{IP}", log_file: str = f"{IP}_result.json") -> Union[dict, None]:
    """
    :input_output: variable -> False if INPUT, True if OUTPUT
        -> INPUT if data is going to be written
        -> OUTPUT if data is going to be read
    """

    if not os.path.isdir(log_dir):
        os.mkdir(log_dir)

    elif not os.path.isfile(log_file) and input_output:
        return {}

    elif replace:
        open(log_file, "w+").close()

    with open(log_file, "a+") as logs:
        if input_output:
            # data will be read
            log_data = json.loads(logs.read())
            return log_data

        else:
            # data will be written
            logs.write(data)


def print_banner(banner: str):
    print(banner)


def logging_console(string: str, mode: str, end="\n"):
    """
    mode: could be CRITICAL, WARNING, NEGATIVE, QUESTION, INFO, VERBOSE or POSITIVE
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


def logging_file(data: str):
    global output
    try:
        if os.path.isfile(output):
            if not overwrite:
                logging_console(
                    f'File "{output}" already exist, do you want to overwrite it: (y/N): ', "QUESTION")
            open(output, "w+").close()

        with open(output, "a+") as logging_file:
            logging_file.write(data)

    except PermissionError:
        logging_console(
            f"Log file '{output}' is protected. Creating '{output}.json'...")
        output += ".json"
        logging_console(data)


def reset_bin():
    answer = ""
    while not answer.startswith("y"):
        answer = logging_console("Reset binary (Y/n/q): ", "QUESTION").lower()
        if answer == "q":
            logging_console("Exiting program by user action", "WARNING")
            exit(0)
