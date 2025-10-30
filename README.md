# Laravel Security Tester

A comprehensive security testing tool for Laravel applications, designed to detect SQL Injection and XSS vulnerabilities. Features a modern GUI with real-time logging, login support, and export capabilities.

## Features

- **SQL Injection Detection**: Tests for error-based and time-based SQL injection vulnerabilities
- **XSS Detection**: Scans for reflected and DOM-based cross-site scripting vulnerabilities
- **Web Crawling**: Automatically discovers and tests forms on your Laravel application
- **Authentication Support**: Login to protected areas before scanning
- **Host Header Support**: Useful for testing local development environments with custom domains
- **Real-time Logging**: Live updates during scanning with color-coded messages
- **Export Reports**: Save results in JSON or HTML format
- **Modern GUI**: Built with ttkbootstrap for a professional interface
- **Local Development Friendly**: Supports self-signed HTTPS certificates and localhost testing

## Requirements

- Python 3.6+
- Dependencies listed in `requirements.txt`

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python laravel_security_tester.py
   ```

## Usage

1. **Target URL**: Enter the base URL of your Laravel application (e.g., `http://localhost:8000`)
2. **Host Header** (optional): Specify a custom Host header for local development (e.g., `myapp.test`)
3. **Login Credentials** (optional): Provide email and password to authenticate before scanning
4. **Crawl Depth**: Set how deep the crawler should follow links (1-10)
5. Click **Start Scan** to begin testing

## How It Works

The tool performs the following steps:

1. **Crawling**: Discovers all forms and links within the specified crawl depth
2. **Authentication**: Logs in using provided credentials if specified
3. **Form Testing**: Tests each discovered form for vulnerabilities
4. **SQL Injection**: Injects various payloads to detect database vulnerabilities
5. **XSS**: Tests for script injection vulnerabilities
6. **Reporting**: Displays results in real-time and allows export

## Supported Vulnerabilities

### SQL Injection
- Error-based SQLi (detects database errors in responses)
- Time-based SQLi (detects delays caused by SLEEP payloads)
- Boolean-based SQLi (detects changes in response behavior)

### XSS
- Reflected XSS (payload appears in response)
- DOM-based XSS (payload executes in browser context)

## Export Options

- **JSON**: Structured data format for programmatic analysis
- **HTML**: Human-readable report with clickable links to vulnerable URLs

## Safety Notice

This tool is intended for security testing of applications you own or have permission to test. Always ensure you have proper authorization before scanning any website or application.

## License

This project is open-source. Use responsibly.