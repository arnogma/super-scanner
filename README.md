
# SSL Checker (Super Scanner)

A simple Python-based SSL checker and mass IP scanner that utilizes `masscan` to scan a list of IP addresses for open ports, specifically targeting SSL-related ports (default is port 443). This tool is useful for network security professionals, penetration testers, or anyone needing to identify live SSL services in a subnet.

## Warning

Before running the code, please use a VPN to avoid getting blacklisted

## Features

- Scans a list of IPs using `masscan`.
- Supports customizable scan rate (number of IPs scanned at once).
- Option to scan specific or all ports.
- Saves the scan results to a specified file.
- Easy-to-use command-line interface (CLI).

## Prerequisites

To use this tool, you need to have the following installed:

- [Python 3](https://www.python.org/downloads/)
- [masscan](https://github.com/robertdavidgraham/masscan) (used for scanning IPs)
  - You can install `masscan` via your package manager or from source.
  - On Ubuntu: `sudo apt install masscan`
  - On macOS: `brew install masscan`

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/ssl-checker.git
   cd ssl-checker
   ```

2. **Install dependencies (if any):**
   - This project uses `argparse` which is a standard Python library, so no additional dependencies are required.

3. **Ensure masscan is installed:**
   - On Ubuntu:
     ```bash
     sudo apt install masscan
     ```
   - On macOS:
     ```bash
     brew install masscan
     ```

## Usage

### Command-line Arguments

The following command-line options are available:

- `-i` or `--input`: The file path containing a list of IP addresses to scan (default is `ips.txt`).
- `-o` or `--output`: The file path where the scan results will be saved (default is `masscan_results.txt`).
- `--rate`: The number of IPs to scan at once (default is `10000`).
- `-p` or `--port`: The port number(s) to scan (default is `443` for HTTPS). You can specify multiple ports, separating each port number by commas (ex. 443, 80, 8080)
- `--all-ports`: An option to scan all ports, overriding the `--ports` option

### Example Usage

To scan a list of IPs in `ips.txt` for port 443 (HTTPS):

```bash
python super-scanner.py -i ips.txt -o masscan_results.txt -p 443
```

To scan a list of IPs for all ports (0-65535) and save the results to `scan_results.txt`:

```bash
python super-scanner.py -i ips.txt -o scan_results.txt -p 0-65535
```

To scan with a custom rate (e.g., 5000 IPs at once):

```bash
python super-scanner.py -i ips.txt -o masscan_results.txt --rate 5000
```

### Create the Required Files

If the input (`ips.txt`) or output (`masscan_results.txt`) files don't exist, they will be automatically created when you run the script.

### Running the Script

Ensure that you're connected to a VPN (if necessary) before running the script, especially if scanning a large range of IPs to avoid being blocked.

```bash
python super-scanner.py
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to fork the repository and submit pull requests. Any suggestions, bug fixes, or improvements are welcome.

## Acknowledgments

- [masscan](https://github.com/robertdavidgraham/masscan) for the IP scanning functionality.
- Python's [argparse](https://docs.python.org/3/library/argparse.html) for command-line argument parsing.
