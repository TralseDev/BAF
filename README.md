# **BAF**

x86 Windows Stack-Based Buffer Overflow scanner in Python.

## Description

BAF is a tool used to scan Winx86 applications for Buffer Overflow Vulnerabilities. It's able to fuzz and exploit vulnerable applications and create a reverse shell.

## Getting Started

### __Warning__
**Use BAF for *educational proposes* only! The contributors *aren't responsible* for the *damage* made by this tool!**

### Installation
Python version 3.0 - 3.10
```
git clone https://github.com/TralseDev/BAF.git
```

### Executing program
```
python3 main.py
```

### Examples:

```
python3 main.py --lhost 127.0.0.1 --lport 1337 --rhost 127.0.0.1 --rport 2337 --prefix="OVERFLOW_COMMAND" --timeout=5 --little-endian
```

![Example video](https://github.com/TralseDev/BAF/blob/main/examples/example.GIF)

## Help

```
python3 main.py -h
```

## Authors

Tralse

## Version History

* 1.2 (14.10.2021)
    * More fixes:
        * Updated logger.py/logging_console() description
        * msfvenom port issues
    * More functions:
        * Updated logger.py/init()
        * Created `--allow-overwrite` flag
        * Created `--no-logging` flag
        * Created `--bypass-logs` flag
        * Updated flags:
            - `--escapeFuzz` -> `--escape-fuzz`
            - `--escapeBadCharDetection` -> `--escape-bcd`
        * Log scans and read them when rescanning binaries to save time
* 1.1 (13.10.2021)
    * Stable version fix:
        * Netcat port issues
        * Banner typo
        * Changed `--escapeFuzz` prefix format (from `lenOfOverflow,offset` to `offset`)
        * Multiple prefix scan (Beta)
    * More functions:
        * Write scan output into file (`-o` flag)
        * Updated logger.py/init() function
* 1.0 (12.10.2021)
    * Stable version
* 0.0
    * Beta phase

## License

This project is licensed under the GNU General Public License v3.0 (GNU GPLv3 License)

## TODOs
- offline scanner + `-r`,`--remote` / `-i`,`--internal` flags (standart is `-r`)
- fuzz max length of chars needed to trigger BOF
- allow to choose reverse shell
- multi-threading
- allow to remove bad char from list
- allow to add multiple chars once
- automatic bad char detection using screen shot!
- add ofuscation and other techniques to bypass AV / Firewall
- automatic binary debug to save time and be more precise
- allow to use proxy