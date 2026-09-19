FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# ── System packages: security tools ──────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv python3-dev \
    build-essential libffi-dev libssl-dev \
    nmap masscan \
    amass subfinder dnsenum fierce arp-scan \
    whatweb gobuster feroxbuster ffuf nikto nuclei wafw00f arjun \
    sqlmap wpscan commix \
    testssl.sh sslscan \
    metasploit-framework hydra netexec evil-winrm \
    john hashcat hashid \
    smbmap nbtscan smbclient enum4linux-ng responder \
    snmp onesixtyone \
    trivy \
    checksec binutils radare2 gdb binwalk \
    foremost testdisk bulk-extractor sleuthkit \
    steghide exiftool \
    sherlock recon-ng theharvester spiderfoot \
    xxd upx-ucl curl wget git jq \
    && rm -rf /var/lib/apt/lists/*

# ── pip-installable security tools (not in Kali repos or need latest) ────────
RUN pip3 install --no-cache-dir --break-system-packages \
    httpx-cli paramspider dalfox nosqlmap tplmap jwt-tool \
    graphql-cop trufflehog censys shodan subjack \
    ROPgadget one_gadget pwntools \
    autorecon gau anew qsreplace uro \
    rustscan katana prowler \
    2>/dev/null || true

WORKDIR /app

# ── Python application dependencies ──────────────────────────────────────────
COPY pyproject.toml ./
RUN rm -rf /usr/lib/python3/dist-packages/starlette* && \
    pip3 install --no-cache-dir --break-system-packages . 2>/dev/null; \
    pip3 install --no-cache-dir --break-system-packages \
    anthropic openai fastapi uvicorn python-dotenv jinja2 pydantic httpx filelock pyyaml starlette==0.48.0

# ── Application code ─────────────────────────────────────────────────────────
COPY . .

EXPOSE 8080

# Run as root — security tools require elevated privileges
CMD ["python3", "-m", "dashboard.app"]
