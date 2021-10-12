import socket
import subprocess


def host_up(ip: str) -> bool:
    """
    return True if host is up, else False
    """
    try:
        test = subprocess.check_output(f"ping -c 3 {ip}").decode()
        if "bytes" in test.lower():
            return True
        else:
            return False
    except:
        return False


def connect(ip_port: tuple, timeout: int = 1) -> socket:
    # just connects
    # :ip_port: should be in format (ip, port), as tuple!
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(ip_port)
    s.recv(1024)
    return s


def recv(buf_size: int, s: socket) -> str:
    # returns recieved data
    return s.recv(buf_size).decode("utf8")


def send(data: str, ip: str, port: int, timeout: int = 1, s: socket = None) -> bool:
    """
    if sended successfully: return true else false
    EXPERIMENTAL: don't set a socket as parameter!
    """
    s = connect((ip, port), timeout=timeout)
    try:
        s.send(bytes(data+"\r\n", encoding="latin1"))
        recv(1024, s)
        return True
    except Exception:
        return False
