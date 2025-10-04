# ReconSociety - Complete User Guide

## 📖 Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Basic Usage](#basic-usage)
4. [Advanced Features](#advanced-features)
5. [Module Details](#module-details)
6. [Configuration](#configuration)
7. [Reporting](#reporting)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

## 🚀 Introduction

ReconSociety is an advanced reconnaissance framework designed for security researchers, bug bounty hunters, and penetration testers. Unlike traditional tools that chain existing utilities, ReconSociety provides a unified approach with original implementations.

### Philosophy
"Reconnaissance is the foundation of all successful security engagements. The quality of your information gathering directly impacts your ability to identify and exploit vulnerabilities."

## 🛠️ Installation

### Automated Installation (Recommended)
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
pip3 install -r requirements.txt
chmod +x recon_society.py
```

### Dependencies
- Python 3.6+
- requests >= 2.28.0
- dnspython >= 2.2.1
- colorama >= 0.4.4
- beautifulsoup4 >= 4.11.1

## 🎯 Basic Usage

### Quick Start
```bash
# Full reconnaissance scan
python3 recon_society.py -t example.com --full

# With output file
python3 recon_society.py -t example.com --full -o results.json

# HTML report
python3 recon_society.py -t example.com --full -f html -o report.html
```

### Command Structure
```
python3 recon_society.py [OPTIONS] -t TARGET

Required:
  -t, --target        Target domain or IP address

Optional:
  -o, --output        Output file path
  -f, --format        Output format (json/html)
  --full             Run complete reconnaissance
  --assets           Asset discovery only
  --vulns            Vulnerability analysis only
  --params           Parameter discovery only
  --endpoints        Endpoint discovery only
  --cloud            Cloud misconfiguration check only
```

## 🔧 Advanced Features

### Multi-Module Scanning
```bash
# Combine specific modules
python3 recon_society.py -t example.com --assets --vulns --endpoints
```

### Custom Configuration
```bash
# Use custom configuration file
python3 recon_society.py -t example.com --config ~/.reconsociety/custom_config.json
```

### Batch Processing
```bash
# Process multiple targets (if implemented)
python3 recon_society.py --target-list targets.txt --full
```

## 📋 Module Details

### 🔍 Asset Discovery Module
**Purpose**: Comprehensive asset enumeration and mapping

**Capabilities**:
- DNS record enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA)
- Subdomain discovery using brute force techniques
- Multi-threaded port scanning (common and custom ports)
- Service identification and version detection

**Usage**:
```bash
python3 recon_society.py -t example.com --assets
```

**Output Example**:
```json
{
  "type": "subdomain",
  "subdomain": "api.example.com",
  "method": "bruteforce",
  "timestamp": "2025-01-04T10:00:00"
}
```

### 🛡️ Vulnerability Analysis Module  
**Purpose**: Identify security vulnerabilities in discovered assets

**Capabilities**:
- SQL injection testing with multiple payload types
- Cross-site scripting (XSS) detection
- Directory traversal vulnerability scanning
- Custom payload generation and testing

**Usage**:
```bash
python3 recon_society.py -t example.com --vulns
```

**Vulnerability Types Detected**:
- **SQL Injection**: Union-based, Boolean-blind, Error-based, Time-based
- **XSS**: Reflected, Stored, DOM-based
- **Path Traversal**: Directory traversal, File inclusion

### 📍 Parameter Discovery Module
**Purpose**: Identify hidden and unlinked parameters

**Capabilities**:
- GET/POST parameter fuzzing
- Response analysis for parameter validation
- Custom wordlist support
- Intelligent parameter detection

**Usage**:
```bash
python3 recon_society.py -t http://example.com --params
```

**Common Parameters Discovered**:
- Authentication: user, admin, token, key
- Data Access: id, page, file, path
- Functionality: debug, test, callback, redirect

### 🗂️ Endpoint Discovery Module
**Purpose**: Enumerate directories, files, and hidden endpoints

**Capabilities**:
- Directory and file brute forcing
- Common endpoint detection
- Status code analysis
- Content-length verification

**Usage**:
```bash
python3 recon_society.py -t http://example.com --endpoints
```

**Common Endpoints**:
- Admin panels: /admin, /dashboard, /panel
- API endpoints: /api, /api/v1, /rest
- Configuration: /config, /.env, /backup
- Development: /test, /debug, /dev

### ☁️ Cloud Security Module
**Purpose**: Detect cloud misconfigurations and exposed resources

**Capabilities**:
- AWS S3 bucket enumeration
- Azure Blob storage detection  
- Access control verification
- Misconfiguration identification

**Usage**:
```bash
python3 recon_society.py -t example.com --cloud
```

**Cloud Resources Checked**:
- S3 buckets: example.com, example-backup, example-data
- Azure blobs: exampledata, examplestorage
- Access permissions and public exposure

## ⚙️ Configuration

### Default Configuration Location
`~/.reconsociety/config.json`

### Configuration Options
```json
{
  "version": "1.0.0",
  "threads": {
    "subdomain_discovery": 20,
    "port_scanning": 50,
    "parameter_fuzzing": 10,
    "endpoint_discovery": 15
  },
  "timeouts": {
    "dns_timeout": 3,
    "http_timeout": 5,
    "port_timeout": 3
  },
  "wordlists": {
    "subdomains": "~/.reconsociety/wordlists/subdomains.txt",
    "parameters": "~/.reconsociety/wordlists/parameters.txt",
    "endpoints": "~/.reconsociety/wordlists/endpoints.txt"
  },
  "output": {
    "default_format": "json",
    "save_location": "~/.reconsociety/reports/"
  }
}
```

### Custom Wordlists
- **Subdomains**: `~/.reconsociety/wordlists/subdomains.txt`
- **Parameters**: `~/.reconsociety/wordlists/parameters.txt`  
- **Endpoints**: `~/.reconsociety/wordlists/endpoints.txt`

## 📊 Reporting

### JSON Report Structure
```json
{
  "scan_info": {
    "tool": "ReconSociety",
    "version": "1.0.0",
    "author": "kernelpanic",
    "organization": "infosbios",
    "timestamp": "2025-01-04T10:00:00"
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
- Interactive elements for detailed analysis
- Export-friendly format
- Professional presentation

## 🐛 Troubleshooting

### Common Issues

#### Installation Problems
```bash
# Issue: pip install fails
# Solution: Update pip and try again
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Issue: Permission denied
# Solution: Don't run as root, use --user flag if needed
pip3 install --user -r requirements.txt
```

#### Runtime Errors
```bash
# Issue: DNS resolution timeouts
# Solution: Increase timeout in config
"timeouts": {"dns_timeout": 10}

# Issue: Too many threads causing errors
# Solution: Reduce thread count
"threads": {"subdomain_discovery": 10}
```

#### Network Issues
```bash
# Issue: Connection refused errors
# Solution: Check target availability and firewall rules

# Issue: Rate limiting
# Solution: Reduce thread count or add delays
```

### Debug Mode
```bash
# Enable verbose logging (if implemented)
python3 recon_society.py -t example.com --full --verbose
```

## ✅ Best Practices

### Pre-Engagement
1. **Always obtain proper authorization** before testing
2. **Scope verification** - Ensure target is within authorized scope
3. **Legal compliance** - Follow all applicable laws and regulations
4. **Documentation** - Keep detailed records of all activities

### During Reconnaissance
1. **Start with passive techniques** to avoid detection
2. **Gradual escalation** from passive to active scanning
3. **Rate limiting** to avoid overwhelming target systems
4. **Regular backups** of reconnaissance data
5. **Organized documentation** of all findings

### Post-Reconnaissance
1. **Data validation** - Verify all discovered assets and vulnerabilities
2. **Priority assessment** - Rank findings by criticality
3. **Report generation** - Create comprehensive documentation
4. **Secure storage** - Protect sensitive reconnaissance data

### Ethical Guidelines
1. **Responsible disclosure** for any vulnerabilities found
2. **Minimal impact** testing to avoid system disruption
3. **Data protection** - Handle any discovered data responsibly
4. **Professional conduct** throughout all engagements

## 🎯 Use Case Scenarios

### Bug Bounty Hunting
```bash
# Comprehensive target assessment
python3 recon_society.py -t target.com --full -o bounty_recon.json

# Focus on web application testing
python3 recon_society.py -t target.com --params --endpoints --vulns
```

### CTF Competitions
```bash
# Quick asset discovery for CTF challenges
python3 recon_society.py -t ctf-target.com --assets --endpoints

# Parameter hunting for hidden flags
python3 recon_society.py -t ctf-target.com --params
```

### Penetration Testing
```bash
# Initial reconnaissance phase
python3 recon_society.py -t client.com --full -f html -o pentest_recon.html

# Focused vulnerability assessment
python3 recon_society.py -t client.com --vulns --cloud
```

## 📞 Support and Community

### Getting Help
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and examples
- **Community**: Join discussions with other security researchers

### Contributing
- **Code contributions**: Submit pull requests with improvements
- **Wordlist additions**: Share custom wordlists
- **Bug reports**: Help improve tool reliability
- **Feature requests**: Suggest new capabilities

### Contact
- **Developer**: kernelpanic
- **Organization**: infosbios
- **Email**: cyb3r-ssrf@proton.me

---

## 🔒 Legal Notice

ReconSociety is designed for educational purposes and authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any targets. The developers are not responsible for any misuse of this tool.

**Always remember**: With great power comes great responsibility. Use these tools ethically and legally.

---

*"The revolution will be digitized"* - fsociety

**⚡ Stay ethical, stay curious, stay secure ⚡**
