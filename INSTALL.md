# 🛠️ Hawkeye Installation Guide

## Quick Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Install FFUF
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install ffuf

# Or download from GitHub (latest version)
wget https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz
tar -xzf ffuf_linux_amd64.tar.gz
sudo mv ffuf /usr/local/bin/
chmod +x /usr/local/bin/ffuf
```

### 4. Verify Installation
```bash
python3 hawkeye.py --help
ffuf -version
```

## Optional: Screenshot Engines

### Playwright (Recommended)
```bash
pip install playwright
playwright install chromium
```

### wkhtmltopdf
```bash
# Ubuntu/Debian
sudo apt install wkhtmltopdf

# macOS
brew install wkhtmltopdf
```

## System Requirements

### Minimum Requirements
- Python 3.8+
- 2GB RAM
- 1GB free disk space
- Linux/macOS (Windows support limited)

### Recommended Requirements
- Python 3.10+
- 4GB RAM
- 5GB free disk space
- SSD storage
- Multiple CPU cores

## Alternative Installation

### Clone Repository
```bash
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye
pip install -r requirements.txt
```

## Troubleshooting

### FFUF Installation Issues
```bash
# Check if FFUF is in PATH
which ffuf

# If not found, add to PATH
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

### Python Dependencies Issues
```bash
# Upgrade pip
pip install --upgrade pip

# Install with user flag
pip install --user -r requirements.txt

# Use virtual environment
python3 -m venv hawkeye-env
source hawkeye-env/bin/activate
pip install -r requirements.txt
```

### Permission Issues
```bash
# For /etc/hosts updates
sudo python3 hawkeye.py http://target.com

# For file permissions
chmod +x hawkeye.py
```

## Development Installation

### Clone and Setup
```bash
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available
```

### Run Tests
```bash
pytest tests/
```

## Wordlists Setup

The repository includes optimized wordlists:
- `subdomains.txt` - 19,966 subdomain entries
- `directories.txt` - 1,273,832 directory entries
- `quick_wordlist.txt` - 1,000 common directories

### Custom Wordlists
Place custom wordlists in the project root:
```bash
cp /path/to/custom/subdomains.txt ./custom_subdomains.txt
cp /path/to/custom/directories.txt ./custom_directories.txt
```

## Configuration

### Environment Variables
```bash
export HAWKEYE_THREADS=100
export HAWKEYE_TIMEOUT=15
export HAWKEYE_OUTPUT_DIR=/path/to/results
```

### Configuration File
Create `hawkeye.conf`:
```ini
[default]
threads = 50
timeout = 10
screenshot_engine = playwright
output_dir = ./results

[fast]
subdomain_lines = 1000
directory_lines = 1000

[deep]
subdomain_lines = 20000
directory_lines = 50000
```

## Verification

### Test Installation
```bash
# Test basic functionality
python3 hawkeye.py http://httpbin.org --fast

# Test with screenshots
python3 hawkeye.py http://httpbin.org --screenshot-engine playwright

# Test subdomain enumeration
python3 hawkeye.py http://httpbin.org --no-screenshots
```

### Expected Output
```
🎯 Target: http://httpbin.org
📁 Results: /path/to/results/2025-01-15_14-30-22
📸 Screenshots: playwright
[+] Hawkeye 2025-01-15_14-30-22 started with 1 seed(s)…
🚀 Starting Hawkeye Scan
```

## Support

If you encounter issues:
1. Check the [Troubleshooting](README.md#troubleshooting) section
2. Open an [Issue](https://github.com/yourusername/hawkeye/issues)
3. Check existing [Discussions](https://github.com/yourusername/hawkeye/discussions)
