# SIPG - Shodan IP Grabber

[![PyPI version](https://badge.fury.io/py/sipg.svg)](https://badge.fury.io/py/sipg)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

![SIPG Banner](banner.jpg)

A professional command-line tool for searching IP addresses using the Shodan API. SIPG provides an intuitive interface for security researchers, penetration testers, and network administrators to discover and analyze internet-connected devices.

## ✨ Features

- 🔍 **Advanced Search**: Powerful query syntax with support for all Shodan search filters
- 📊 **Rich Output**: Beautiful tables and detailed information display
- 💾 **Flexible Export**: Save results to files in various formats
- ⚡ **Rate Limiting**: Built-in API rate limiting to respect Shodan's limits
- 🔐 **Secure Configuration**: Secure API key storage in user's home directory
- 🌍 **Cross-Platform**: Works on Windows, macOS, and Linux
- 📈 **Progress Tracking**: Real-time progress indicators for long searches
- 🎯 **Multiple Output Formats**: Simple IP lists, detailed results, or formatted tables

## 🚀 Quick Start

### Installation

#### From PyPI (Recommended)
```bash
pip install sipg
```

#### From Source
```bash
git clone https://github.com/emptymahbob/sipg.git
cd sipg
pip install -e .
```

### Configuration

1. Get your Shodan API key from [shodan.io](https://account.shodan.io/)
2. Configure SIPG with your API key:
```bash
sipg configure
```

### Basic Usage

```bash
# Search for IPs with SSL certificates from Uber
sipg search 'ssl:"Uber Technologies Inc"'

# Search with detailed information
sipg search 'http.server:Apache' --details

# Display results in a table format
sipg search 'port:80' --table

# Save results to a file
sipg search 'country:"United States"' -o results.txt

# Limit results and add delay
sipg search 'product:"nginx"' -m 50 -d 2.0
```

## 📖 Commands

### `sipg configure`
Configure your Shodan API key securely.

### `sipg search <query>`
Search for IP addresses using Shodan.

**Options:**
- `-o, --output FILE`: Save results to file
- `-m, --max-results N`: Maximum number of results
- `-d, --delay SECONDS`: Delay between API requests
- `--details`: Show detailed results
- `--table`: Display results in table format

### `sipg info`
Show information about your Shodan API key and usage.

### `sipg examples`
Display example search queries.

### `sipg clear`
Clear the stored API key.

## 🔍 Search Query Examples

```bash
# SSL certificates
sipg search 'ssl:"Uber Technologies Inc"'
sipg search 'ssl.cert.subject.CN:"*.uber.com"'

# HTTP servers
sipg search 'http.server:Apache'
sipg search 'http.status:200'

# Geographic location
sipg search 'country:"United States"'
sipg search 'city:"New York"'

# Port scanning
sipg search 'port:80'
sipg search 'port:443'

# Products and services
sipg search 'product:"nginx"'
sipg search 'product:"MySQL"'

# Organizations
sipg search 'org:"Amazon"'
sipg search 'org:"Google"'

# Complex queries
sipg search 'ssl:"Uber Technologies Inc" http.status:200'
sipg search 'port:80 -http.title:"Invalid URL"'
```

## 🛠️ Development

### Setup Development Environment
```bash
git clone https://github.com/emptymahbob/sipg.git
cd sipg
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest
```

### Code Formatting
```bash
black sipg/
```

### Type Checking
```bash
mypy sipg/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

- **Author**: Mahbob Alam (@emptymahbob)
- **Email**: emptymahbob@gmail.com
- **Twitter**: https://x.com/emptymahbob
- **Issues**: https://github.com/emptymahbob/sipg/issues

## ⚠️ Disclaimer

This tool is for educational and authorized security research purposes only. Always ensure you have proper authorization before scanning any networks or systems. The authors are not responsible for any misuse of this tool.
