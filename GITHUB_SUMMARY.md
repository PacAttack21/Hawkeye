# 🦅 Hawkeye v2.0 - GitHub Ready!

## 📁 Repository Structure

Your GitHub repository is ready with these essential files:

### Core Files
- **`hawkeye.py`** - Main scanner script (84KB)
- **`requirements.txt`** - Python dependencies (just `rich>=13.0.0`)
- **`subdomains.txt`** - 19,966 subdomain entries (148KB)
- **`directories.txt`** - 1,273,832 directory entries (14MB)
- **`quick_wordlist.txt`** - 1,000 common directories (1.7KB)

### Documentation
- **`README.md`** - Comprehensive documentation with usage examples
- **`INSTALL.md`** - Detailed installation guide
- **`CHANGELOG.md`** - Version history and changes
- **`CONTRIBUTING.md`** - Contribution guidelines
- **`LICENSE`** - MIT License

### Configuration
- **`.gitignore`** - Git ignore rules for Python projects

## 🚀 How Users Will Use It

### Simple Download & Run
```bash
# Download the files
wget https://raw.githubusercontent.com/yourusername/hawkeye/main/hawkeye.py
wget https://raw.githubusercontent.com/yourusername/hawkeye/main/requirements.txt
wget https://raw.githubusercontent.com/yourusername/hawkeye/main/subdomains.txt
wget https://raw.githubusercontent.com/yourusername/hawkeye/main/directories.txt

# Install dependencies
pip install -r requirements.txt

# Install FFUF
sudo apt install ffuf

# Run the scanner
python3 hawkeye.py http://target.com
```

### Or Clone Repository
```bash
git clone https://github.com/yourusername/hawkeye.git
cd hawkeye
pip install -r requirements.txt
python3 hawkeye.py http://target.com
```

## ✨ Key Features

- **Super Simple**: Just 1 Python dependency (`rich`)
- **Self-Contained**: All wordlists included
- **Competition Ready**: Optimized for CPTC/CTF
- **Real-time Progress**: Live URL updates
- **Smart Subdomain Enum**: FFUF with wildcard filtering
- **Automatic /etc/hosts**: Updates discovered subdomains
- **Multiple Screenshot Engines**: Playwright, wkhtmltopdf, curl fallback
- **Periodic Reports**: HTML, JSON, Markdown reports

## 📊 File Sizes

- `hawkeye.py`: 84KB (main script)
- `subdomains.txt`: 148KB (19,966 entries)
- `directories.txt`: 14MB (1.2M+ entries)
- `quick_wordlist.txt`: 1.7KB (1,000 entries)
- Total: ~15MB (perfect for GitHub)

## 🎯 Usage Examples

```bash
# Basic scan
python3 hawkeye.py http://target.com

# Fast scan
python3 hawkeye.py http://target.com --fast

# Deep scan
python3 hawkeye.py http://target.com --deep

# Background mode
python3 hawkeye.py http://target.com --background

# Resume scan
python3 hawkeye.py http://target.com --resume
```

## 🏆 Perfect for:

- **Penetration Testing Competitions** (CPTC, CTF)
- **Bug Bounty Hunting**
- **Web Application Security Testing**
- **Reconnaissance**
- **Educational Purposes**

## 📝 Next Steps

1. **Create GitHub Repository**
2. **Upload all files**
3. **Update README.md** with your actual GitHub username
4. **Create first release** (v2.0.0)
5. **Share with the community!**

---

**Your Hawkeye scanner is ready to soar! 🦅**
