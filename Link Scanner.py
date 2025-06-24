import requests
import re
from urllib.parse import urlparse

def check_url(url):
    """Check if a URL might be a phishing attempt"""

    print(f"\nChecking: {url}")

    # Basic checks
    if not url.startswith(('http://', 'https://')):
        print("⚠️ Warning: URL should start with http:// or https://")

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # Common phishing indicators
    suspicious_keywords = [
        'login', 'account', 'verify', 'bank', 'paypal',
        'secure', 'update', 'confirm', 'password', 'amazon'
    ]

    short_domains = [
        'bit.ly', 'goo.gl', 'tinyurl.com',
        'ow.ly', 't.co', 'is.gd'
    ]

    # Check 1: Suspicious keywords in domain
    for keyword in suspicious_keywords:
        if keyword in domain:
            print(f"⚠️ Suspicious keyword '{keyword}' found in domain name")

    # Check 2: URL shortening services
    for short_domain in short_domains:
        if short_domain in domain:
            print(f"⚠️ URL uses shortening service: {short_domain}")

    # Check 3: HTTPS (secure connection)
    if not url.startswith('https://'):
        print("⚠️ Not using HTTPS (secure connection)")
    else:
        print("✅ Using HTTPS (secure connection)")

    # Check 4: IP address instead of domain
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    if ip_pattern.match(domain.split(':')[0]):
        print("⚠️ URL uses IP address directly (suspicious)")

    # Check 5: Too many subdomains
    if domain.count('.') > 2:
        print("⚠️ Many subdomains (could be suspicious)")

    # Check 6: Try to get page content
    try:
        response = requests.get(url, timeout=5)

        # Check for login forms
        if 'login' in response.text.lower() or 'password' in response.text.lower():
            print("⚠️ Login form detected on page")

        # Check for common phishing phrases
        phishing_phrases = [
            'your account', 'verify now', 'click here',
            'urgent action required', 'security alert'
        ]

        for phrase in phishing_phrases:
            if phrase in response.text.lower():
                print(f"⚠️ Phishing phrase detected: '{phrase}'")

    except requests.exceptions.RequestException as e:
        print(f"⚠️ Could not check page content: {e}")

    print("\nScan complete!")

def main():
    print("=== Phishing Link Scanner ===")
    print("This tool checks for common signs of phishing websites.\n")

    while True:
        url = input("Enter URL to check (or 'q' to quit): ").strip()

        if url.lower() == 'q':
            break

        if not url:
            print("Please enter a URL")
            continue

        check_url(url)

        print("\n" + "="*50 + "\n")

if __name__ == "__main__":
    main()
