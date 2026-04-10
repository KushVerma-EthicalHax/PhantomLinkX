import validators
import socket
import whois
import tldextract
import requests
from colorama import Fore, Style, init

init(autoreset=True)

# -------------------------------
# BANNER (DANGEROUS STYLE)
# -------------------------------
def banner():
    print(Fore.RED + r"""
██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝

        ☠️  PhantomLinkX - Phishing Analyzer ☠️
        🛡️ Cybersecurity | Threat Detection Tool
    """ + Style.RESET_ALL)

# -------------------------------
# URL INPUT
# -------------------------------
def get_url():
    url = input(Fore.YELLOW + "🔗 Enter URL to analyze: ")

    if not validators.url(url):
        print(Fore.RED + "❌ Invalid URL. Try again.")
        return None

    return url

# -------------------------------
# EXPAND URL
# -------------------------------
def expand_url(url):
    try:
        response = requests.get(url, timeout=5)
        return response.url
    except:
        return url

# -------------------------------
# DOMAIN
# -------------------------------
def extract_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

# -------------------------------
# IP
# -------------------------------
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unable to resolve IP"

# -------------------------------
# WHOIS
# -------------------------------
def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "registrar": str(w.registrar)
        }
    except:
        return {"error": "WHOIS lookup failed"}

# -------------------------------
# IP INFO
# -------------------------------
def get_ip_info(ip):
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json")
        return res.json()
    except:
        return {}

# -------------------------------
# KEYWORD CHECK
# -------------------------------
def check_keywords(url):
    suspicious_words = ["login", "verify", "update", "bank", "free", "urgent", "otp", "kyc"]
    return [w for w in suspicious_words if w in url.lower()]

# -------------------------------
# RISK CALCULATION
# -------------------------------
def calculate_risk(keywords, whois_data):
    score = 0
    reasons = []

    if keywords:
        score += 30
        reasons.append("Suspicious keywords in URL")

    if "creation_date" in whois_data:
        if whois_data["creation_date"] != "None":
            if "2025" in whois_data["creation_date"] or "2026" in whois_data["creation_date"]:
                score += 25
                reasons.append("Recently registered domain")

    return score, reasons

# -------------------------------
# MAIN
# -------------------------------
def main():
    banner()

    print(Fore.MAGENTA + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(Fore.CYAN + "🔍 Starting Analysis...")
    print(Fore.MAGENTA + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    url = get_url()
    if not url:
        return

    # Expand URL
    url = expand_url(url)
    print(Fore.BLUE + f"\n🔗 Expanded URL: {url}")

    # Domain
    domain = extract_domain(url)
    print(Fore.GREEN + f"🌍 Domain: {domain}")

    # IP
    ip = get_ip(domain)
    print(Fore.CYAN + f"📡 IP Address: {ip}")

    # IP Info
    print(Fore.MAGENTA + "\n🌍 IP Info:")
    ip_info = get_ip_info(ip)
    for k, v in ip_info.items():
        print(Fore.WHITE + f"   {k}: {v}")

    # WHOIS
    print(Fore.MAGENTA + "\n📄 WHOIS Info:")
    whois_data = get_whois(domain)
    for k, v in whois_data.items():
        print(Fore.WHITE + f"   {k}: {v}")

    # Keywords
    keywords = check_keywords(url)
    if keywords:
        print(Fore.YELLOW + f"\n⚠️ Suspicious Keywords Found: {keywords}")
    else:
        print(Fore.GREEN + "\n✅ No suspicious keywords")

    # Risk
    score, reasons = calculate_risk(keywords, whois_data)

    print(Fore.MAGENTA + "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(Fore.CYAN + "🔍 Risk Analysis Report")
    print(Fore.MAGENTA + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    print(Fore.WHITE + f"Score: {score}")

    for r in reasons:
        print(Fore.YELLOW + f" - {r}")

    if score > 70:
        print(Fore.RED + "\n🚨 HIGH RISK - PHISHING DETECTED ☠️")
    elif score > 30:
        print(Fore.YELLOW + "\n⚠️ SUSPICIOUS - BE CAUTIOUS")
    else:
        print(Fore.GREEN + "\n✅ SAFE - NO MAJOR THREATS")

# -------------------------------
if __name__ == "__main__":
    main()
