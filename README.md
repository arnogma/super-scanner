# SSL Checker (Super Scanner)

A simple Python-based SSL checker and mass IP scanner that utilizes `masscan` to scan a list of IP addresses for open ports, specifically targeting SSL-related ports (default is port 443). This tool is useful for network security professionals, penetration testers, or anyone needing to identify live SSL services in a subnet.

## Warning

Please install and activate a VPN before executing with this tool, you WILL get blacklisted if you don't 

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
