# ReconSociety - Advanced Reconnaissance Framework

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗  ██████╗██╗███████╗████████╗██╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔════╝██║██╔════╝╚══██╔══╝╚██╗ ██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗██║   ██║██║     ██║█████╗     ██║    ╚████╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║██║   ██║██║     ██║██╔══╝     ██║     ╚██╔╝  
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║╚██████╔╝╚██████╗██║███████╗   ██║      ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝╚═╝╚══════╝   ╚═╝      ╚═╝   
```

**Advanced Reconnaissance Framework for Bug Bounty, CTF, and Penetration Testing**

Developed by **kernelpanic** | Product of **infosbios**

## 🚀 Overview

ReconSociety is a comprehensive reconnaissance framework designed for security researchers, bug bounty hunters, and penetration testers. Unlike traditional tools that simply chain existing utilities, ReconSociety provides a unified approach to vulnerability discovery with fresh, original code implementations.

### ⭐ Key Features

- **🔍 Unified Reconnaissance**: All-in-one approach to asset discovery and vulnerability detection
- **⚡ Multi-threaded Scanning**: High-performance concurrent operations
- **🎯 Comprehensive Coverage**: SQL injection, XSS, directory traversal, parameter discovery
- **☁️ Cloud Misconfiguration Detection**: AWS S3, Azure Blob storage enumeration
- **📊 Advanced Reporting**: JSON and HTML report generation
- **🔧 Modular Architecture**: Extensible framework for custom modules
- **🎨 Mr. Robot Inspired**: Clean, hacker-aesthetic interface

## 🛠️ Installation

### Quick Installation

```bash
git clone https://github.com/cyb3r-al3rt/ReconSociety.git
cd ReconSociety
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
git clone https://github.com/cyb3r-al3rt/ReconSociety.git
cd ReconSociety
pip install -r requirements.txt
chmod +x recon_society.py
```

## 📋 Usage

### Basic Usage

```bash
# Full reconnaissance scan
python3 recon_society.py -t example.com --full

# Asset discovery only
python3 recon_society.py -t example.com --assets

# Vulnerability analysis
python3 recon_society.py -t example.com --vulns

# Parameter discovery
python3 recon_society.py -t example.com --params

# Endpoint discovery  
python3 recon_society.py -t example.com --endpoints

# Cloud misconfiguration check
python3 recon_society.py -t example.com --cloud
```

### Advanced Options

```bash
# Generate HTML report
python3 recon_society.py -t example.com --full -f html -o report.html

# JSON output to file
python3 recon_society.py -t example.com --full -o results.json
```

### Command Line Options

```
-t, --target        Target domain or IP address (required)
-o, --output        Output file for results
-f, --format        Output format (json, html)
--full             Run full reconnaissance suite
--assets           Asset discovery only
--vulns            Vulnerability analysis only  
--params           Parameter discovery only
--endpoints        Endpoint discovery only
--cloud            Cloud misconfiguration check only
```

## 🔧 Modules

### 🔍 Asset Discovery
- DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)
- Subdomain discovery using brute force
- Multi-threaded port scanning
- Service identification

### 🛡️ Vulnerability Analysis
- SQL injection detection with multiple payloads
- Cross-site scripting (XSS) testing
- Directory traversal vulnerability scanning
- Custom payload generation

### 📍 Parameter Discovery
- GET/POST parameter fuzzing
- Common parameter wordlist testing
- Response analysis for parameter validation

### 🗂️ Endpoint Discovery
- Directory and file enumeration
- Common endpoint detection
- Status code analysis
- Content-length verification

### ☁️ Cloud Security
- AWS S3 bucket enumeration
- Azure Blob storage detection
- Access control verification
- Misconfiguration identification

## 📊 Reporting

ReconSociety generates comprehensive reports in multiple formats:

### JSON Report Structure
```json
{
  "scan_info": {
    "tool": "ReconSociety",
    "version": "1.0.0",
    "author": "kernelpanic",
    "organization": "infosbios",
    "timestamp": "2025-01-01T12:00:00"
  },
  "summary": {
    "total_assets": 25,
    "total_vulnerabilities": 5,
    "total_parameters": 12,
    "total_endpoints": 18,
    "total_cloud_resources": 3
  },
  "results": {
    "assets": [...],
    "vulnerabilities": [...],
    "parameters": [...],
    "endpoints": [...],
    "cloud_resources": [...]
  }
}
```

### HTML Report Features
- Dark theme with hacker aesthetic
- Organized sections for each module
- Detailed vulnerability information
- Export-friendly format

## 🎯 Use Cases

### Bug Bounty Hunting
- Comprehensive target reconnaissance
- Automated vulnerability discovery
- Parameter and endpoint enumeration
- Cloud asset identification

### CTF Competitions
- Quick asset discovery
- Vulnerability assessment
- Hidden endpoint detection
- Service enumeration

### Penetration Testing
- Initial reconnaissance phase
- Vulnerability validation
- Asset mapping
- Security assessment

## ⚠️ Legal Disclaimer

ReconSociety is designed for educational purposes and authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any targets. The developers are not responsible for any misuse of this tool.

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

**kernelpanic** - Security Researcher & Developer  
Product of **infosbios**

## 🙏 Acknowledgments

- Inspired by Mr. Robot's hacker aesthetic
- Built for the security research community
- Dedicated to advancing ethical hacking practices

## 📞 Support

For support, questions, or feature requests:
- Open an issue on GitHub
- Contact: cyb3r-ssrf@proton.me

---

*"The revolution will be digitized"* - fsociety

**⚡ Stay ethical, stay curious, stay secure ⚡**
