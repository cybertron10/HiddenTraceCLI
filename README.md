# HiddenTrace CLI

A powerful command-line tool that combines web crawling, parameter extraction, parameter fuzzing, and XSS scanning capabilities into a single binary.

## Features

- **Web Crawling**: Intelligent crawling to discover URLs and endpoints
- **Parameter Extraction**: Extract parameters from forms, URLs, and JavaScript
- **Parameter Fuzzing**: Discover hidden parameters using wordlists
- **XSS Scanning**: Context-aware XSS vulnerability detection using Playwright
- **Concurrent Processing**: Configurable concurrency for faster scanning
- **Headless Browser Support**: Uses Playwright for advanced browser automation

## Installation

### Prerequisites

- Go 1.22 or higher
- Playwright browsers (installed automatically on first run)

### Build from Source

```bash
git clone https://github.com/cybertron10/HiddenTraceCLI.git
cd HiddenTraceCLI
go mod tidy
go build -o hiddentrace-cli.exe
```

## Usage

```bash
./hiddentrace-cli.exe -url https://example.com [options]
```

### Options

- `-url string`: Target URL or domain to scan (required)
- `-concurrency int`: Number of concurrent scans (default: 5)
- `-headless`: Use headless browser (default: true)
- `-fast-mode`: Enable fast mode payload set (default: false)
- `-ultra-fast`: Enable ultra fast mode (default: false)
- `-timeout duration`: Scan timeout (default: 10m)

### Examples

```bash
# Basic scan
./hiddentrace-cli.exe -url https://example.com

# High concurrency scan
./hiddentrace-cli.exe -url https://example.com -concurrency 10

# Fast mode scan
./hiddentrace-cli.exe -url https://example.com -fast-mode

# Save output to file
./hiddentrace-cli.exe -url https://example.com -concurrency 10 > scan_results.txt 2>&1
```

## How It Works

1. **Crawling**: Discovers all accessible URLs and endpoints on the target domain
2. **Parameter Discovery**: Extracts parameters from forms, query strings, and JavaScript
3. **Parameter Fuzzing**: Uses wordlists to discover hidden parameters
4. **XSS Scanning**: Performs context-aware XSS testing using Playwright browser automation
5. **Results**: Provides detailed output of discovered vulnerabilities

## Architecture

The tool integrates components from:
- **HiddenTrace**: Web crawling and parameter extraction
- **xss-scanner-minimal**: Playwright-based XSS scanning with context detection

## Security Features

- SSRF prevention in crawling
- URL validation and sanitization
- Context-aware XSS payload selection
- WAF detection and evasion techniques
- Rate limiting and timeout controls

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built on top of [HiddenTrace](https://github.com/cybertron10/HiddenTrace)
- XSS scanning powered by [xss-scanner-minimal](https://github.com/cybertron10/xss-scanner-minimal)
- Uses [Playwright](https://playwright.dev/) for browser automation
