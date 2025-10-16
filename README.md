# HiddenTrace CLI

A powerful command-line tool that combines web crawling, parameter extraction, parameter fuzzing, and XSS scanning capabilities into a single binary.

## Features

- **Web Crawling**: Intelligent crawling to discover URLs and endpoints
- **Parameter Extraction**: Extract parameters from forms, URLs, and JavaScript
- **Parameter Fuzzing**: Discover hidden parameters using wordlists (25,000+ parameters)
- **XSS Scanning**: Context-aware XSS vulnerability detection using Playwright
- **Concurrent Processing**: Configurable concurrency for faster scanning
- **Headless Browser Support**: Uses Playwright for advanced browser automation
- **Comprehensive Output**: Multiple output files with detailed results
- **Progress Tracking**: Real-time progress updates during scanning phases

## Installation

### Prerequisites

- Go 1.22 or higher
- Playwright browsers (installed automatically on first run)

### Option 1: Direct Install (Recommended)

```bash
go install github.com/cybertron10/HiddenTraceCLI@latest
```

**Note**: The binary will be installed as `HiddenTraceCLI.exe` in your Go bin directory. You may need to add `$GOPATH/bin` to your PATH environment variable to run it from anywhere.

### Option 2: Build from Source

```bash
git clone https://github.com/cybertron10/HiddenTraceCLI.git
cd HiddenTraceCLI
go mod tidy
go build -o hiddentrace-cli.exe
```

## Usage

After installation, you can run the tool directly:

```bash
# If installed via go install (Windows)
HiddenTraceCLI.exe -url https://example.com [options]

# If installed via go install (Linux/Mac)
HiddenTraceCLI -url https://example.com [options]

# If built from source
./hiddentrace-cli.exe -url https://example.com [options]
```

### Options

- `-url string`: Target URL or domain to scan (required if -file not specified)
- `-file string`: File containing list of URLs to scan (one per line, required if -url not specified)
- `-concurrency int`: Number of concurrent scans (default: 10)
- `-headless`: Use headless browser (default: true)
- `-fast-mode`: Enable fast mode payload set (default: false)
- `-ultra-fast`: Enable ultra fast mode (default: false)
- `-timeout duration`: Scan timeout (default: 10m)
- `-output string`: Output directory for results (default: "scan_results")
- `-wordlist string`: Path to parameter wordlist file (default: "wordlist.txt")

### Examples

```bash
# Basic scan (after go install)
HiddenTraceCLI.exe -url https://example.com

# Scan multiple URLs from file
HiddenTraceCLI.exe -file urls.txt

# High concurrency scan
HiddenTraceCLI.exe -url https://example.com -concurrency 10

# Fast mode scan
HiddenTraceCLI.exe -url https://example.com -fast-mode

# Custom output directory and wordlist
HiddenTraceCLI.exe -url https://example.com -output my_results -wordlist custom_wordlist.txt

# Scan multiple URLs with custom settings
HiddenTraceCLI.exe -file urls.txt -output batch_results -concurrency 15

# Save console output to file
HiddenTraceCLI.exe -url https://example.com -concurrency 10 > console_output.txt 2>&1
```

## How It Works

1. **Phase 1 - Crawling**: Discovers all accessible URLs and endpoints on the target domain
2. **Phase 2 - Parameter Extraction**: Extracts parameters from forms, query strings, and JavaScript
3. **Phase 3 - Parameter Fuzzing**: Uses wordlists (25,000+ parameters) to discover hidden parameters
4. **Phase 4 - XSS Scanning**: Performs context-aware XSS testing using Playwright browser automation
5. **Results**: Generates comprehensive output files with detailed results

## Output Files

After scan completion, only one file is saved in the output directory:

- **`xss_vulnerabilities.txt`**: XSS vulnerabilities found with exploit URLs and payloads

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
