# 🦅 Hawkeye v2.0 — Super Fast CPTC Scanner

A high-performance web reconnaissance tool designed specifically for penetration testing competitions. Hawkeye combines subdomain enumeration, directory fuzzing, and automated documentation in a streamlined, efficient package.

## 🚀 Features

- **Multi-phase Scanning**: Quick wins → Deep scanning phases
- **Smart Subdomain Enumeration**: FFUF-based with wildcard filtering
- **Automatic /etc/hosts Updates**: Resolves discovered subdomains
- **Real-time Progress Tracking**: Live URL updates and progress indicators
- **Periodic Report Generation**: HTML, JSON, and Markdown reports
- **Competition-Ready**: Optimized for CPTC and similar competitions
- **Resume Capability**: Save and resume scans
- **Screenshot Capture**: Multiple engines (Playwright, wkhtmltopdf, curl fallback)
- **Priority Scoring**: Automatically categorizes findings by importance

## 📋 Requirements

### System Requirements
- Python 3.8+
- Linux/macOS (Windows support limited)
- FFUF (fast web fuzzer)
- curl
- Optional: Playwright, wkhtmltopdf for screenshots

### Python Dependencies
```bash
pip install -r requirements.txt
```

## 🛠️ Installation

1. **Download the files:**
```bash
# Download hawkeye.py, requirements.txt, and wordlists
wget https://raw.githubusercontent.com/yourusername/hawkeye/main/hawkeye.py
wget https://raw.githubusercontent.com/yourusername/hawkeye/main/requirements.txt
wget https://raw.githubusercontent.com/yourusername/hawkeye/main/subdomains.txt
wget https://raw.githubusercontent.com/yourusername/hawkeye/main/directories.txt
```

2. **Install Python dependencies:**
```bash
pip install -r requirements.txt
```

3. **Install FFUF:**
```bash
# Ubuntu/Debian
sudo apt install ffuf

# Or download from GitHub
wget https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz
tar -xzf ffuf_linux_amd64.tar.gz
sudo mv ffuf /usr/local/bin/
```

4. **Optional - Install screenshot tools:**
```bash
# Playwright (recommended)
pip install playwright
playwright install chromium

# wkhtmltopdf
sudo apt install wkhtmltopdf
```

## 🎯 Quick Start

### Basic Usage
```bash
# Simple scan
python3 hawkeye.py http://target.com

# Fast scan (1000 subdomains, quick wordlist)
python3 hawkeye.py http://target.com --fast

# Deep scan (full wordlists, comprehensive)
python3 hawkeye.py http://target.com --deep

# Background mode (runs continuously)
python3 hawkeye.py http://target.com --background

# Resume a previous scan
python3 hawkeye.py http://target.com --resume
```

### Advanced Usage
```bash
# Custom wordlists
python3 hawkeye.py http://target.com --wordlist /path/to/dirs.txt --subdomain-wordlist /path/to/subs.txt

# Custom threads and timeouts
python3 hawkeye.py http://target.com --threads 100 --timeout 15

# No screenshots (faster)
python3 hawkeye.py http://target.com --no-screenshots

# Different screenshot engine
python3 hawkeye.py http://target.com --screenshot-engine playwright
```

## 📊 Scan Phases

### Phase 0: Subdomain Enumeration
- Uses FFUF with Host header fuzzing
- Filters out wildcard responses
- Automatically updates /etc/hosts
- Tests reachability before adding to scan queue

### Phase 1: Quick Wins
- Fast directory fuzzing with common wordlists
- Screenshots and documentation
- Real-time progress updates
- Priority scoring

### Phase 2: Deep Scanning (optional)
- Comprehensive wordlist scanning
- Recursive directory discovery
- Extended timeout periods
- Full documentation

## 📁 Output Structure

```
results/2025-01-15_14-30-22/
├── artifacts/
│   ├── ffuf/           # FFUF scan results
│   ├── subdomains/     # Subdomain enumeration results
│   └── raw/            # Raw baseline captures
├── findings/
│   ├── bodies/         # HTTP response bodies
│   ├── headers/        # HTTP headers
│   ├── shots/          # Screenshots
│   └── curl/           # Curl command logs
├── reports/
│   ├── report.html     # HTML report
│   ├── report.json     # JSON data
│   └── competition_report.md
├── urls_found.txt      # Live URL list
├── urls_simple.txt     # Simple URL list
└── hawkeye_log.ndjson  # Detailed logs
```

## 🎛️ Command Line Options

### Basic Options
- `target` - Target URL (required)
- `--fast` - Fast scan mode (1000 subdomains, quick wordlist)
- `--deep` - Deep scan mode (full wordlists, comprehensive)
- `--background` - Run continuously in background
- `--resume` - Resume previous scan

### Customization
- `--wordlist` - Custom directory wordlist
- `--subdomain-wordlist` - Custom subdomain wordlist
- `--threads` - Number of threads (default: 50)
- `--timeout` - Request timeout (default: 10)
- `--output` - Custom output directory

### Screenshots
- `--no-screenshots` - Disable screenshots
- `--screenshot-engine` - Engine: playwright, wkhtmltopdf, curl

### Advanced
- `--no-subdomains` - Skip subdomain enumeration
- `--subfinder-only` - Use only subfinder (if available)

## 📈 Progress Tracking

The scanner provides real-time progress updates:

```
📊 Quick Wins: 2/4 (50.0%) | 1 subdomains, 8 findings | 🔍 http://target.com/admin/ (quick)
```

- **Progress**: Current job / Total jobs (percentage)
- **Subdomains**: Number of discovered subdomains
- **Findings**: Number of discovered URLs
- **Current URL**: What's being fuzzed right now

## 🏆 Competition Tips

### For CPTC/CTF Competitions:
1. **Start early**: Run `--background` mode at competition start
2. **Use fast mode**: `--fast` for quick initial reconnaissance
3. **Monitor reports**: Check `urls_found.txt` periodically
4. **Resume capability**: Use `--resume` if scans are interrupted
5. **Screenshot everything**: Helps with manual analysis

### Wordlist Recommendations:
- **Subdomains**: Use SecLists subdomain wordlists
- **Directories**: Use SecLists directory wordlists
- **Custom**: Add competition-specific terms

## 🔧 Configuration

### Environment Variables
```bash
export HAWKEYE_THREADS=100
export HAWKEYE_TIMEOUT=15
export HAWKEYE_OUTPUT_DIR=/path/to/results
```

### Custom Wordlists
Place custom wordlists in the project directory:
- `subdomains.txt` - Subdomain enumeration
- `directories.txt` - Directory fuzzing
- `quick_wordlist.txt` - Fast mode wordlist

## 🐛 Troubleshooting

### Common Issues

**FFUF not found:**
```bash
sudo apt install ffuf
# or download from GitHub releases
```

**Permission denied for /etc/hosts:**
```bash
# Run with sudo to update /etc/hosts
sudo python3 hawkeye.py http://target.com
```

**Screenshots not working:**
```bash
# Install Playwright
pip install playwright
playwright install chromium

# Or use curl fallback
python3 hawkeye.py http://target.com --screenshot-engine curl
```

**Out of memory:**
```bash
# Reduce threads
python3 hawkeye.py http://target.com --threads 20
```

## 📝 Logs and Debugging

### Log Levels
- **INFO**: Normal operation
- **WARN**: Non-critical issues
- **ERROR**: Critical failures

### Log Files
- `hawkeye_log.ndjson` - Structured logs
- `urls_found.txt` - Live URL discoveries
- FFUF logs in `artifacts/ffuf/`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [FFUF](https://github.com/ffuf/ffuf) - Fast web fuzzer
- [SecLists](https://github.com/danielmiessler/SecLists) - Wordlists
- [Playwright](https://playwright.dev/) - Screenshot engine
- [Rich](https://rich.readthedocs.io/) - Terminal formatting

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/hawkeye/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/hawkeye/discussions)

---

**Made for penetration testers, by penetration testers.** 🦅