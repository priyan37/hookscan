import re
import socket
import requests
import whois
import time
import datetime
import ssl
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from bs4 import BeautifulSoup

console = Console()
GOOGLE_SAFE_BROWSING_API_KEY = "your_api_key_here"

def print_banner():
    banner = """
██╗  ██╗ ██████╗  ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║  ██║██╔═══██╗██╔═══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║██║   ██║██║   ██║█████╔╝ ███████╗██║     ███████║██╔██╗ ██║
██╔══██║██║   ██║██║   ██║██╔═██╗ ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║╚██████╔╝╚██████╔╝██║  ██╗███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                    """
    console.print(Panel(banner, title="AegisZ", style="bold blue"))

def progress_task(task_name):
    with Progress() as progress:
        task = progress.add_task(f"[cyan]{task_name}...", total=10)
        for _ in range(10):
            time.sleep(0.1)
            progress.update(task, advance=1)

def check_google_safe_browsing(url):
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {"clientId": "hookscan", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        result = response.json()
        return bool(result.get("matches", []))
    except requests.exceptions.HTTPError as e:
        console.print(f"[bold red]HTTP Error: {e}[/bold red]")
    except requests.exceptions.ConnectionError:
        console.print("[bold red]Connection Error: Unable to reach Google Safe Browsing API.[/bold red]")
    except requests.exceptions.Timeout:
        console.print("[bold red]Request Timeout: Google Safe Browsing API took too long to respond.[/bold red]")
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error checking Google Safe Browsing: {e}[/bold red]")
    return False

def check_domain_age(url):
    try:
        domain = urlparse(url).hostname
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return False
        age_days = (datetime.datetime.utcnow() - creation_date).days
        return age_days < 180
    except Exception:
        return False

def check_ssl_certificate(url):
    try:
        domain = urlparse(url).hostname
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
        return False
    except Exception:
        return True

def check_google_index(url):
    search_url = f"https://www.google.com/search?q=site:{url}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(search_url, headers=headers, timeout=10)
        response.raise_for_status()
        return "did not match any documents" in response.text.lower()
    except requests.exceptions.RequestException as e:
        console.print(f"[bold red]Error checking Google Index: {e}[/bold red]")
        return False

def check_shortened_url(url):
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'shorte.st', 'adf.ly', 'cutt.ly', 'v.gd', 'rb.gy', 'soo.gd']
    return urlparse(url).hostname in shorteners

def phishing_detection(url):
    console.print("\n[bold yellow]Running Phishing Detection Checks...[/bold yellow]")
    progress_task("Analyzing URL")
    
    checks = {
        "Young domain (under 6 months)": check_domain_age(url),
        "Flagged by Google Safe Browsing": check_google_safe_browsing(url),
        "Not indexed in Google": check_google_index(url),
        "Shortened URL": check_shortened_url(url),
        "No SSL Certificate": check_ssl_certificate(url),
    }
    
    table = Table(title="Phishing Check Report", show_header=True, header_style="bold magenta")
    table.add_column("Check", justify="left")
    table.add_column("Result", justify="center")
    
    risk_score = 0
    risk_weights = {
        "Flagged by Google Safe Browsing": 5,
        "Shortened URL": 3,
        "Young domain (under 6 months)": 2,
        "Not indexed in Google": 1,
        "No SSL Certificate": 2,
    }
    
    for check, result in checks.items():
        table.add_row(check, "[green]No[/green]" if not result else "[red]Yes[/red]")
        if result:
            risk_score += risk_weights.get(check, 0)
    
    console.print(table)
    
    if risk_score >= 5:
        console.print("\n[bold red]⛔ HIGH RISK: Phishing site detected![/bold red]")
    elif risk_score >= 3:
        console.print("\n[bold yellow]🚨 WARNING: This site looks suspicious.[/bold yellow]")
    elif risk_score >= 2:
        console.print("\n[bold cyan]⚠️ CAUTION: Some risk factors detected.[/bold cyan]")
    else:
        console.print("\n[bold green]✅ SAFE: No major issues detected.[/bold green]")

def main():
    print_banner()
    while True:
        console.print("\n[bold cyan]1. Check a URL[/bold cyan]")
        console.print("[bold cyan]2. Exit[/bold cyan]")
        choice = input("Select an option: ").strip()
        if choice == "1":
            user_url = input("Enter URL to check: ").strip()
            phishing_detection(user_url)
        elif choice == "2":
            console.print("[bold green]Exiting...[/bold green]")
            break
        else:
            console.print("[bold red]Invalid option! Try again.[/bold red]")

if __name__ == "__main__":
    main()
