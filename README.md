# BEAST SCANNER - GitHub README.md

```markdown
<div align="center">

![Beast Scanner Banner](https://img.shields.io/badge/BEAST-SCANNER-00ff41?style=for-the-badge&logo=hackthebox&logoColor=white)

# 🔥 BEAST SCANNER v2.0

### Advanced Web Application Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-blue?style=for-the-badge)]()
[![Maintenance](https://img.shields.io/badge/Maintained-Yes-00ff41?style=for-the-badge)]()

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=22&pause=1000&color=00FF41&center=true&vCenter=true&width=600&lines=Advanced+Web+Vulnerability+Scanner;SQL+Injection+%7C+XSS+%7C+LFI+%7C+RCE;Modern+Hacking+Theme+GUI;For+Authorized+Pentesting+Only" alt="Typing SVG" />

<br>

```
██████╗ ███████╗ █████╗ ███████╗████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝█████╗  ███████║███████╗   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██████╔╝███████╗██║  ██║███████║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

**A powerful, feature-rich GUI-based web application vulnerability scanner with a modern cyberpunk hacking theme. Designed for security professionals and penetration testers.**

[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[Screenshots](#-screenshots) •
[Documentation](#-documentation) •
[Contributing](#-contributing)

---

</div>

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/beast-scanner.git

# Navigate to directory
cd beast-scanner

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python beast_scanner.py
```

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Screenshots](#-screenshots)
- [Scan Modules](#-scan-modules)
- [Configuration](#-configuration)
- [Export Options](#-export-options)
- [Documentation](#-documentation)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)

---

## 🚀 Features

<table>
<tr>
<td>

### 🎯 Vulnerability Detection
- **SQL Injection** - Error, Time, Union based
- **Cross-Site Scripting (XSS)** - Reflected, Stored, DOM
- **Local File Inclusion (LFI)**
- **Remote Code Execution (RCE)**
- **Server-Side Template Injection (SSTI)**
- **Open Redirect Vulnerabilities**
- **CORS Misconfiguration**
- **Security Header Analysis**

</td>
<td>

### 🛠️ Advanced Features
- **Multi-threaded Scanning**
- **Custom Payload Support**
- **Proxy Integration**
- **Session Management**
- **Cookie Analysis**
- **SSL/TLS Inspection**
- **Port Scanning**
- **Technology Detection**

</td>
</tr>
<tr>
<td>

### 🎨 Modern UI/UX
- **Cyberpunk Hacking Theme**
- **Animated Indicators**
- **Real-time Statistics**
- **Interactive Charts**
- **Glow Effect Buttons**
- **Dark Mode Interface**
- **Responsive Design**
- **Tabbed Navigation**

</td>
<td>

### 📊 Reporting
- **JSON Export**
- **HTML Reports**
- **TXT Reports**
- **Severity Filtering**
- **Detailed Evidence**
- **Timestamp Logging**
- **Executive Summary**
- **Remediation Tips**

</td>
</tr>
</table>

---

## 💻 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Git (optional)

### Method 1: Clone Repository

```bash
# Clone the repository
git clone https://github.com/yourusername/beast-scanner.git

# Change directory
cd beast-scanner

# Install required packages
pip install -r requirements.txt

# Run the application
python beast_scanner.py
```

### Method 2: Download ZIP

1. Download the ZIP file from the [Releases](https://github.com/yourusername/beast-scanner/releases) page
2. Extract the contents
3. Open terminal in the extracted folder
4. Run `pip install -r requirements.txt`
5. Run `python beast_scanner.py`

### Requirements

Create a `requirements.txt` file:

```txt
requests>=2.28.0
beautifulsoup4>=4.11.0
dnspython>=2.2.0
urllib3>=1.26.0
colorama>=0.4.5
```

### Platform-Specific Instructions

<details>
<summary><b>🪟 Windows</b></summary>

```powershell
# Using PowerShell
git clone https://github.com/yourusername/beast-scanner.git
cd beast-scanner
pip install -r requirements.txt
python beast_scanner.py
```

</details>

<details>
<summary><b>🐧 Linux</b></summary>

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install python3 python3-pip python3-tk git
git clone https://github.com/yourusername/beast-scanner.git
cd beast-scanner
pip3 install -r requirements.txt
python3 beast_scanner.py
```

</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
# Using Homebrew
brew install python3 python-tk git
git clone https://github.com/yourusername/beast-scanner.git
cd beast-scanner
pip3 install -r requirements.txt
python3 beast_scanner.py
```

</details>

---

## 🎮 Usage

### Basic Usage

1. **Launch the Application**
   ```bash
   python beast_scanner.py
   ```

2. **Enter Target URL**
   - Input your target URL in the target field
   - Example: `https://example.com`

3. **Configure Scan Options**
   - Navigate to the Scanner tab
   - Select desired vulnerability checks
   - Adjust advanced settings if needed

4. **Start Scan**
   - Click the "⚡ START SCAN" button
   - Monitor progress in the Console tab

5. **Review Results**
   - Check the Dashboard for statistics
   - View detailed findings in Results tab
   - Export reports as needed

### Command Line Arguments (Optional)

```bash
# Basic scan
python beast_scanner.py

# With debug mode
python beast_scanner.py --debug

# Specify target directly
python beast_scanner.py --target https://example.com
```

---

## 📸 Screenshots

<div align="center">

### 🏠 Dashboard View
![Dashboard](screenshots/dashboard.png)
*Real-time vulnerability statistics with interactive charts*

### 🎯 Scanner Configuration
![Scanner](screenshots/scanner.png)
*Comprehensive scan options and advanced settings*

### 📋 Results View
![Results](screenshots/results.png)
*Detailed vulnerability findings with filtering options*

### 💻 Console Output
![Console](screenshots/console.png)
*Live scan progress and detailed logging*

### ⚙️ Settings Panel
![Settings](screenshots/settings.png)
*Customizable scanner configuration*

</div>

> **Note:** To add screenshots, create a `screenshots` folder and add your images.

---

## 🔍 Scan Modules

### Vulnerability Scanners

| Module | Description | Severity Detection |
|--------|-------------|-------------------|
| 🔴 SQL Injection | Tests for SQL injection vulnerabilities using error-based, time-based, and union-based techniques | Critical |
| 🟠 XSS | Detects reflected, stored, and DOM-based cross-site scripting | High |
| 🔴 LFI/RFI | Local and Remote File Inclusion testing | Critical |
| 🔴 RCE | Remote Code Execution vulnerability detection | Critical |
| 🔴 SSTI | Server-Side Template Injection testing | Critical |
| 🟡 Open Redirect | URL redirect vulnerability scanning | Medium |
| 🟡 CORS | Cross-Origin Resource Sharing misconfiguration | Medium |
| 🟢 Headers | Security header analysis and recommendations | Low-Medium |

### Discovery Modules

| Module | Description |
|--------|-------------|
| 📁 Directory Enumeration | Discovers hidden directories and admin panels |
| 📄 Sensitive Files | Detects exposed configuration and backup files |
| 🔌 Port Scanner | Identifies open ports and running services |
| 🔧 Tech Detection | Identifies frameworks, CMS, and technologies |
| 🔒 SSL/TLS Analysis | Certificate validation and configuration check |
| 🍪 Cookie Analysis | Security flag verification for cookies |

---

## ⚙️ Configuration

### Scanner Settings

```python
# Default configuration
config = {
    "timeout": 10,           # Request timeout in seconds
    "threads": 20,           # Concurrent threads
    "user_agent": "Mozilla/5.0...",
    "verify_ssl": False,     # SSL verification
    "follow_redirects": True,
    "max_depth": 3           # Crawl depth
}
```

### Custom Payloads

Add custom payloads by editing the scanner class:

```python
# Add to VulnerabilityScanner class
self.custom_sql_payloads = [
    "' OR '1'='1",
    "admin'--",
    # Add your payloads here
]
```

### Proxy Configuration

```python
# In Settings tab or code
proxy = "http://127.0.0.1:8080"  # Burp Suite
proxy = "socks5://127.0.0.1:9050"  # Tor
```

---

## 📤 Export Options

### JSON Export
```json
{
  "target": "https://example.com",
  "scan_time": "2024-01-15T10:30:00",
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "CRITICAL",
      "url": "https://example.com/page?id=1",
      "details": "Error-based SQL injection detected",
      "evidence": "MySQL error in response"
    }
  ]
}
```

### HTML Report
- Professional styled report
- Executive summary
- Detailed findings
- Remediation recommendations
- Charts and statistics

### Text Report
- Simple text format
- Easy to parse
- Suitable for automation

---

## 📚 Documentation

### Project Structure

```
beast-scanner/
├── 📄 beast_scanner.py      # Main application
├── 📄 requirements.txt      # Dependencies
├── 📄 README.md            # Documentation
├── 📄 LICENSE              # MIT License
├── 📁 screenshots/         # Screenshot images
│   ├── dashboard.png
│   ├── scanner.png
│   ├── results.png
│   └── console.png
├── 📁 payloads/           # Custom payload files
│   ├── sql.txt
│   ├── xss.txt
│   └── lfi.txt
├── 📁 reports/            # Generated reports
└── 📁 logs/               # Scan logs
```

### Class Reference

| Class | Description |
|-------|-------------|
| `CyberTheme` | UI theme configuration and colors |
| `AnimatedLabel` | Label with typing animation effect |
| `GlowButton` | Custom button with glow hover effect |
| `PulsingIndicator` | Animated status indicator |
| `VulnerabilityScanner` | Core scanning engine |
| `BeastScannerGUI` | Main application GUI |

---

## 🗺️ Roadmap

### Version 2.1 (Upcoming)
- [ ] API scanning support
- [ ] GraphQL vulnerability testing
- [ ] JWT token analysis
- [ ] Subdomain enumeration
- [ ] WAF detection and bypass

### Version 2.2 (Planned)
- [ ] Automated exploitation
- [ ] Custom scripting engine
- [ ] Plugin system
- [ ] Cloud deployment option
- [ ] Team collaboration features

### Version 3.0 (Future)
- [ ] AI-powered vulnerability detection
- [ ] Machine learning payload generation
- [ ] Advanced reporting dashboard
- [ ] Integration with bug bounty platforms

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### How to Contribute

1. **Fork the Repository**
   ```bash
   git fork https://github.com/yourusername/beast-scanner.git
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make Changes**
   - Write clean, documented code
   - Follow PEP 8 style guidelines
   - Add tests if applicable

4. **Commit Changes**
   ```bash
   git commit -m "Add: Amazing new feature"
   ```

5. **Push to Branch**
   ```bash
   git push origin feature/amazing-feature
   ```

6. **Open Pull Request**
   - Describe your changes
   - Reference any related issues

### Contribution Guidelines

- 📝 Follow the existing code style
- 📚 Update documentation as needed
- 🧪 Test your changes thoroughly
- 💬 Write meaningful commit messages
- 🔍 Check for existing issues before creating new ones

### Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 Beast Scanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## ⚠️ Disclaimer

<div align="center">

### 🚨 IMPORTANT: READ BEFORE USE 🚨

</div>

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   This tool is provided for EDUCATIONAL and AUTHORIZED SECURITY TESTING     ║
║   purposes ONLY. The developers assume NO responsibility for misuse of      ║
║   this software.                                                             ║
║                                                                              ║
║   By using this tool, you agree to:                                          ║
║                                                                              ║
║   ✓ Only scan systems you own or have explicit written permission to test   ║
║   ✓ Comply with all applicable local, state, and federal laws               ║
║   ✓ Use this tool responsibly and ethically                                 ║
║   ✓ Not use this tool for malicious purposes                                ║
║                                                                              ║
║   Unauthorized access to computer systems is ILLEGAL and punishable by law. ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Legal Notice

- 🔴 **DO NOT** use this tool on systems without authorization
- 🔴 **DO NOT** use this tool for illegal activities
- 🔴 **DO NOT** use this tool to harm others
- 🟢 **DO** obtain proper written permission before testing
- 🟢 **DO** use responsibly in controlled environments
- 🟢 **DO** report vulnerabilities responsibly

---

## 🙏 Acknowledgments

- Thanks to all contributors who have helped improve this project
- Inspired by the cybersecurity community
- Built with ❤️ for security professionals

---

## 📞 Contact & Support

<div align="center">

[![GitHub Issues](https://img.shields.io/badge/GitHub-Issues-red?style=for-the-badge&logo=github)](https://github.com/yourusername/beast-scanner/issues)
[![GitHub Discussions](https://img.shields.io/badge/GitHub-Discussions-blue?style=for-the-badge&logo=github)](https://github.com/yourusername/beast-scanner/discussions)
[![Twitter](https://img.shields.io/badge/Twitter-Follow-1DA1F2?style=for-the-badge&logo=twitter)](https://twitter.com/yourusername)

</div>

- 🐛 **Bug Reports:** [GitHub Issues](https://github.com/yourusername/beast-scanner/issues)
- 💡 **Feature Requests:** [GitHub Discussions](https://github.com/yourusername/beast-scanner/discussions)
- 📧 **Email:** your.email@example.com

---

<div align="center">

### ⭐ Star this repository if you find it useful!

![GitHub Stars](https://img.shields.io/github/stars/yourusername/beast-scanner?style=social)
![GitHub Forks](https://img.shields.io/github/forks/yourusername/beast-scanner?style=social)
![GitHub Watchers](https://img.shields.io/github/watchers/yourusername/beast-scanner?style=social)

---

**Made with 💚 by Security Enthusiasts**

*Happy Hacking! 🔥*

</div>
```

---

## Additional Files to Create

### 📄 LICENSE

```
MIT License

Copyright (c) 2024 Beast Scanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 📄 requirements.txt

```txt
requests>=2.28.0
beautifulsoup4>=4.11.0
dnspython>=2.2.0
urllib3>=1.26.0
colorama>=0.4.5
```

### 📄 .gitignore

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Logs and reports
logs/
reports/
*.log

# OS
.DS_Store
Thumbs.db

# Environment
.env
.env.local
*.pem
*.key
```

### 📄 CONTRIBUTING.md

```markdown
# Contributing to Beast Scanner

Thank you for your interest in contributing!

## How to Contribute

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Code Style

- Follow PEP 8
- Use meaningful variable names
- Add comments for complex logic
- Write docstrings for functions

## Reporting Bugs

Use GitHub Issues with:
- Clear title
- Steps to reproduce
- Expected vs actual behavior
- Screenshots if applicable
```

---

## 📁 Repository Structure

```
beast-scanner/
├── beast_scanner.py
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
└── screenshots/
    ├── dashboard.png
    ├── scanner.png
    ├── results.png
    └── console.png
```

This README provides a professional, comprehensive overview of your project that will look great on GitHub! 🚀
