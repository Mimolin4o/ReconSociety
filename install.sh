#!/bin/bash

# ReconSociety Installation Script
# Developed by kernelpanic | Product of infosbios

echo "
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗  ██████╗██╗███████╗████████╗██╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔════╝██║██╔════╝╚══██╔══╝╚██╗ ██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗██║   ██║██║     ██║█████╗     ██║    ╚████╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║██║   ██║██║     ██║██╔══╝     ██║     ╚██╔╝  
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║╚██████╔╝╚██████╗██║███████╗   ██║      ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝  ╚═════╝╚═╝╚══════╝   ╚═╝      ╚═╝   

ReconSociety Installation Script
Developed by kernelpanic | Product of infosbios
"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] Starting ReconSociety installation...${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}[!] Please don't run this script as root${NC}"
   exit 1
fi

# Check Python version
echo -e "${BLUE}[*] Checking Python installation...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d" " -f2 | cut -d"." -f1,2)
    echo -e "${GREEN}[+] Python3 found: $(python3 --version)${NC}"

    # Check if Python version is 3.6 or higher
    if python3 -c "import sys; exit(0 if sys.version_info >= (3,6) else 1)"; then
        echo -e "${GREEN}[+] Python version is compatible${NC}"
    else
        echo -e "${RED}[!] Python 3.6 or higher required${NC}"
        exit 1
    fi
else
    echo -e "${RED}[!] Python3 not found. Please install Python3.6 or higher${NC}"
    exit 1
fi

# Check if pip is installed
echo -e "${BLUE}[*] Checking pip installation...${NC}"
if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}[+] pip3 found${NC}"
else
    echo -e "${RED}[!] pip3 not found. Please install pip3${NC}"
    exit 1
fi

# Install required packages
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
if pip3 install -r requirements.txt; then
    echo -e "${GREEN}[+] Dependencies installed successfully${NC}"
else
    echo -e "${RED}[!] Failed to install dependencies${NC}"
    exit 1
fi

# Make the main script executable
echo -e "${BLUE}[*] Setting permissions...${NC}"
chmod +x recon_society.py

# Create symbolic link for easy access
echo -e "${BLUE}[*] Creating symbolic link...${NC}"
if [ ! -f "/usr/local/bin/reconsociety" ]; then
    sudo ln -sf "$(pwd)/recon_society.py" /usr/local/bin/reconsociety
    echo -e "${GREEN}[+] Symbolic link created. You can now run 'reconsociety' from anywhere${NC}"
fi

# Create configuration directory
echo -e "${BLUE}[*] Creating configuration directory...${NC}"
mkdir -p ~/.reconsociety
mkdir -p ~/.reconsociety/wordlists
mkdir -p ~/.reconsociety/reports

# Create default configuration
cat > ~/.reconsociety/config.json << EOF
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
EOF

# Create basic wordlists
echo -e "${BLUE}[*] Creating wordlists...${NC}"

# Subdomain wordlist
cat > ~/.reconsociety/wordlists/subdomains.txt << 'EOF'
www
api
mail
ftp
admin
test
staging
dev
app
portal
dashboard
blog
shop
secure
support
help
docs
beta
demo
m
mobile
www2
ns1
ns2
mx
smtp
pop
imap
webmail
cpanel
whm
autodiscover
autoconfig
EOF

# Parameter wordlist
cat > ~/.reconsociety/wordlists/parameters.txt << 'EOF'
id
user
admin
test
debug
page
file
path
url
redirect
return
callback
jsonp
search
q
query
keyword
term
filter
sort
order
limit
offset
token
key
secret
password
pwd
pass
username
email
name
data
value
param
EOF

# Endpoint wordlist  
cat > ~/.reconsociety/wordlists/endpoints.txt << 'EOF'
admin
api
login
dashboard
panel
config
backup
test
debug
dev
staging
phpinfo
info
status
health
metrics
docs
swagger
api-docs
robots.txt
sitemap.xml
.env
.git
.svn
wp-admin
wp-content
uploads
images
css
js
assets
static
public
private
tmp
temp
cache
log
logs
EOF

echo -e "${GREEN}[+] Installation completed successfully!${NC}"
echo -e "${YELLOW}[*] Usage: python3 recon_society.py -t example.com --full${NC}"
echo -e "${YELLOW}[*] Or simply: reconsociety -t example.com --full${NC}"
echo -e "${BLUE}[*] Configuration saved to ~/.reconsociety/${NC}"
echo ""
echo -e "${GREEN}Happy hacking! - kernelpanic${NC}"
