from logger import logging_console
from connector import send
import time
from colorama import *


def fuzz(prefix, ip, port, timeout, buffer_count=0) -> int:
    init()
    # fuzzing function
    buffer = prefix+" "+"A"*buffer_count
    for _ in range(1000):
        logging_console(
            f"Fuzzing with {Fore.CYAN}{len(buffer)-len(prefix)-1} bytes", "VERBOSE")
        if not send(buffer, ip, port, timeout):
            logging_console(
                f"Fuzzing crashed at {Fore.RED}{len(buffer)-len(prefix)-1} bytes", "CRITICAL")
            return len(buffer)-len(prefix)-1
        buffer += "A"*100
        time.sleep(timeout)
    return -1
