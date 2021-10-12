from logger import *
import threading
import os
import subprocess


class NCNotFound(Exception):
    """
    Raises when netcat isn't found
    """


def _netcat(port: int, binary_path: str = "/usr/bin/netcat") -> None:
    try:
        os.system(f"/bin/bash -c '{binary_path} -lnvp {port}'")

    except:
        terminals = ["gnome-terminal -x", "xterm -e", "x-terminal-emulator -e"]
        # check if terminals are installed:
        installed = False
        terminal_to_use = ""
        for terminal in terminals:
            if os.path.isfile(f"/usr/share/applications/{terminal[:-3]}"):
                installed = True
                terminal_to_use = terminal

        if not installed:
            answer = ""
            while answer not in ["y", "n"]:
                answer = logging_console(
                    "There was no terminal found to start a new netcat window, wanna install x-terminal-emulator (Y/n): ", "QUESTION").lower()
            if answer == "n":
                answer = ""
                while answer not in ["y", "n"]:
                    answer = logging_console(
                        "There was no terminal found to start a new netcat window, are you sure to not install x-terminal-emulator and to exit (y/N): ", "QUESITON").lower()

                if answer == "n":
                    logging_console(
                        "No terminal was found to execute netcat, exiting...", "NEGATIVE")
                    exit()

                else:
                    logging_console(
                        "Type in root password for apt:", "WARNING")
                    os.system("sudo apt install x-terminal-emulator -y")
                    logging_console(
                        "Installed x-terminal-emulator successfully!", "INFO")
                    terminal_to_use = "x-terminal-emulator -e"


def netcat(port: int, binary_path: str = "/usr/bin/netcat") -> None:
    threading.Thread(target=_netcat, args=([port, binary_path])).start()
