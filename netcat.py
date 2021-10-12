import subprocess
from logger import *
import threading


class NCNotFound(Exception):
    """
    Raises when netcat isn't found
    """


def netcat(port: int, binary_path: str = "/usr/bin/netcat") -> None:
    try:
        threading.Thread(target=subprocess.call, args=(
            [binary_path, f"-lnvp {port}"]))
    except FileNotFoundError:
        raise NCNotFound("netcat isn't installed or wrong binary path")
