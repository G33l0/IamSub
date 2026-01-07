#!/usr/bin/env python3
import argparse
import sys
import os
import time
import json
import socket
import requests
import concurrent.futures
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

# -------------------------------------------------------------------------
# CONFIGURATION & CONSTANTS
# -------------------------------------------------------------------------
VERSION = "1.1.0"
USER_AGENT = f"IamSub-SecurityTool/{VERSION} (Authorized Defensive Testing)"
RESULTS_DIR = "results"
TIMEOUT = 5

# ASCII Banner replicating the attached image style
BANNER = f"""
{Fore.GREEN}
●   ●●●   ●●●● ●●   ●●●● ●  ● ●●●
●  ●   ●  ● ● ● ●  ●     ●  ● ●  ●
●  ●   ●  ● ● ● ●   ●●●  ●  ● ●●●
●  ●●●●●  ● ● ● ●      ● ●  ● ●  ●
●  ●   ●  ●     ●  ●●●●   ●●  ●●●
{Style.RESET_ALL}
      {Fore.WHITE}IamSub v{VERSION} - Defensive Reconnaissance Tool{Style.RESET_ALL}
"""

# -------------------------------------------------------------------------
# CORE CLASSES
# -------------------------------------------------------------------------

class SubdomainEnumerator:
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()

    def fetch_crtsh(self):
        """Query crt.sh for certificate transparency logs."""
        print(f"{Fore.CYAN}[*] Querying Certificate Transparency logs (crt.sh)...")
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            resp = requests.get(url, timeout=10, headers={'User-Agent': USER_AGENT})
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry['name_value']
                    # Handle multi-line entries
                    for sub in name_value.split('\n'):
                        if self.domain in sub and '*' not in sub:
                            self.subdomains.add(sub.strip().lower())
                print(f"{Fore.GREEN}[+] Found {len(self.subdomains)} unique subdomains via Passive Source.")
            else:
                print(f"{Fore.RED}[!] crt.sh returned status {resp.status_code}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error querying crt.sh: {e}")

    def generate_permutations(self):
        """Generate common environment permutations (defensive check for shadow IT)."""
        print(f"{Fore.CYAN}[*] Generating heuristic permutations (dev, staging, test)...")
        prefixes = ['dev', 'stg', 'stage', 'prod', 'test', 'admin', 'vpn', 'api']
        base_count = len(self.subdomains)
        
        # If no subdomains found yet, use base domain
        if not self.subdomains:
            targets = [self.domain]
        else:
            targets = list(self.subdomains)

        for t in targets:
            # simple strategy: prepend prefixes to the domain part
            parts = t.split('.')
            if len(parts) >= 2:
                for p in prefixes:
                    perm = f"{p}-{parts[0]}.{'.'.join(parts[1:])}"
                    self.subdomains.add(perm)
        
        print(f"{Fore.GREEN}[+] Added permutations. Total potential targets: {len(self.subdomains)}")

    def run(self):
        self.fetch_crtsh()
        self.generate_permutations()
        return list(self.subdomains)

class LiveChecker:
    def __init__(self, subdomains):
        self.subdomains = subdomains
        self.results = []

    def check_host(self, sub):
        """Check if host resolves and responds to HTTP/HTTPS."""
        # 1. DNS Resolution Check
        try:
            socket.gethostbyname(sub)
        except socket.gaierror:
            return None # DNS failed

        # 2. HTTP Probe
        protocols = ['https', 'http']
        for proto in protocols:
            url = f"{proto}://{sub}"
            try:
                r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={'User-Agent': USER_AGENT})
                return {
                    "subdomain": sub,
                    "url": url,
                    "status": r.status_code,
                    "server": r.headers.get('Server', 'Unknown'),
                    "title": "N/A" # Simplified for this snippet
                }
            except requests.RequestException:
                continue
        return None

    def run(self):
        print(f"{Fore.CYAN}[*] Probing liveness for {len(self.subdomains)} targets...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.check_host, sub) for sub in self.subdomains]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    self.results.append(res)
                    color = Fore.GREEN if res['status'] == 200 else (Fore.YELLOW if res['status'] in [403, 401] else Fore.RED)
                    print(f"{color}[{res['status']}] {res['subdomain']}")
        return self.results

class Analyzer:
    @staticmethod
    def analyze_status(code):
        if code == 200:
            return "Resource is publicly accessible. Ensure no sensitive data is exposed."
        elif code == 404:
            return "Resource not found. Check for broken links or misconfigured routing. Potential subdomain takeover risk if CNAME exists but resource is deleted."
        elif code == 403:
            return "Forbidden. Access controls are in place, but existence is confirmed. Verify WAF rules and directory listing settings."
        elif code in [301, 302]:
            return "Redirect. Ensure open redirects are not possible."
        elif code >= 500:
            return "Server Error. Indicates application instability or misconfiguration. Debug mode might be enabled."
        return "Unknown status code."

# -------------------------------------------------------------------------
# CLI FUNCTIONS
# -------------------------------------------------------------------------

def save_results(domain, results, analysis_map):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_path = os.path.join(RESULTS_DIR, f"{domain}_{timestamp}")
    
    # Create directory structure
    paths = {
        "200": os.path.join(base_path, "200-live"),
        "403": os.path.join(base_path, "403-forbidden"),
        "404": os.path.join(base_path, "404-analysis"),
        "other": os.path.join(base_path, "other-codes")
    }
    for p in paths.values():
        os.makedirs(p, exist_ok=True)

    # Distribute results
    for res in results:
        code = res['status']
        content = json.dumps(res, indent=4)
        filename = f"{res['subdomain']}.json"
        
        if code == 200:
            with open(os.path.join(paths["200"], filename), 'w') as f: f.write(content)
        elif code == 403:
            with open(os.path.join(paths["403"], filename), 'w') as f: f.write(content)
        elif code == 404:
            with open(os.path.join(paths["404"], filename), 'w') as f: f.write(content)
        else:
            with open(os.path.join(paths["other"], filename), 'w') as f: f.write(content)

    # Generate Main Report
    report_path = os.path.join(base_path, "REPORT.md")
    with open(report_path, 'w') as f:
        f.write(f"# IamSub Analysis Report: {domain}\n")
        f.write(f"**Date:** {datetime.now()}\n\n")
        f.write("## Executive Summary\n")
        f.write(f"Total Live Hosts: {len(results)}\n\n")
        f.write("## Risk Analysis by Status Code\n")
        
        codes = {}
        for r in results:
            c = r['status']
            codes[c] = codes.get(c, 0) + 1
        
        for c, count in codes.items():
            f.write(f"### Status {c} ({count} hosts)\n")
            f.write(f"> **Insight:** {Analyzer.analyze_status(c)}\n\n")
            f.write("| Subdomain | Server |\n|---|---|\n")
            for r in results:
                if r['status'] == c:
                    f.write(f"| {r['subdomain']} | {r['server']} |\n")
            f.write("\n")

    print(f"\n{Fore.GREEN}[+] Results saved to: {base_path}")
    print(f"{Fore.GREEN}[+] Report generated: {report_path}")

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="IamSub - Defensive Subdomain Enumeration & Analysis")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: enumerate
    parser_enum = subparsers.add_parser("enumerate", help="Find subdomains")
    parser_enum.add_argument("domain", help="Target domain")

    # Command: livecheck
    parser_live = subparsers.add_parser("livecheck", help="Check liveness of a domain list")
    parser_live.add_argument("domain", help="Target domain (runs enumeration first internally)")

    # Automatic Workflow (Default if just domain provided, handled via logic below)
    # We add a generic argument to the main parser to capture the 'automatic' use case
    parser.add_argument("--target", help="Run full automatic workflow on this domain")
    
    args = parser.parse_args()

    # Handle "iamsub <domain>" style which argparse doesn't natively do easily without subcommands
    # If no subcommand is passed but a target is (or just sys.argv processing)
    if len(sys.argv) == 2 and sys.argv[1] not in ['-h', '--help', 'enumerate', 'livecheck']:
        target_domain = sys.argv[1]
        run_full_workflow(target_domain)
    elif args.command == "enumerate":
        enum = SubdomainEnumerator(args.domain)
        results = enum.run()
        print(f"\n{Fore.WHITE}Found {len(results)} candidates.{Style.RESET_ALL}")
    elif args.command == "livecheck":
        print(f"{Fore.YELLOW}Note: In standalone mode, livecheck performs enumeration first.{Style.RESET_ALL}")
        run_full_workflow(args.domain)
    elif args.target:
        run_full_workflow(args.target)
    else:
        if len(sys.argv) > 1 and sys.argv[1] not in ['-h', '--help']:
             pass 
        else:
            parser.print_help()

def run_full_workflow(domain):
    print(f"{Fore.BLUE}=== Starting Full Defensive Workflow for: {domain} ==={Style.RESET_ALL}")
    
    # Step 1: Enumerate
    enum = SubdomainEnumerator(domain)
    subs = enum.run()
    
    if not subs:
        print(f"{Fore.RED}[-] No subdomains found. Exiting.")
        return

    # Step 2: Live Check
    checker = LiveChecker(subs)
    live_results = checker.run()
    
    if not live_results:
        print(f"{Fore.RED}[-] No live hosts found from candidates.")
        return

    # Step 3, 4, 5, 6: Categorize, Analyze, Report, Export
    save_results(domain, live_results, Analyzer)
    
    print(f"{Fore.BLUE}=== Workflow Complete ==={Style.RESET_ALL}")

if __name__ == "__main__":
    main()
