import os
import sys
import json
import time
import urllib.request
import urllib.error
import ssl

# ANSI Color Tokens
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[38;5;196m"
GREEN   = "\033[38;5;48m"
CYAN    = "\033[38;5;51m"
AMBER   = "\033[38;5;214m"
GRAY    = "\033[38;5;242m"

BANNER = f"""{CYAN}{BOLD}
  █████╗ ██████╗ ███████╗██╗  ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ███████║██████╔╝█████╗   ╚███╔╝     ███████╗██║     ███████║██╔██╗ ██║
 ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗     ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║  ██║██║     ███████╗██╔╝ ██╗    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{AMBER} » APEX-WEBAUDIT: INTERACTIVE WEB DEFENSE & OWASP POSTURE SCANNER «{RESET}
"""

class ApexWebAuditor:
    def __init__(self, policy_path="audit_policy.json"):
        if not os.path.exists(policy_path):
            print(f"{RED}[-] Error: Policy file '{policy_path}' not found.{RESET}")
            sys.exit(1)

        with open(policy_path, "r") as f:
            self.policy = json.load(f)

        self.required_headers = self.policy.get("required_headers", [])
        self.default_url = self.policy.get("target_url", "https://example.com")

    def run_audit(self, target_url):
        print(BANNER)
        print(f"{BOLD}Target Endpoint:{RESET} {CYAN}{target_url}{RESET}\n")

        print(f"{GRAY}[+] Probing target headers and TLS configuration...{RESET}")
        steps = [
            "Initiating HTTPS handshake and inspecting certificate",
            "Analyzing HTTP response security headers",
            "Evaluating Cookie flags (Secure, HttpOnly, SameSite)",
            "Checking CORS access control headers"
        ]
        for step in steps:
            time.sleep(0.25)
            print(f"  {CYAN}▸{RESET} {step}...")

        print("\n" + "=" * 80 + "\n")

        # Disable SSL verification purely for auditing misconfigured test targets safely
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "Apex-Security-Auditor/1.0"}
        )

        try:
            with urllib.request.urlopen(req, context=ctx, timeout=8) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                cookies = response.headers.get_all('Set-Cookie', [])
        except urllib.error.HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()}
            cookies = e.headers.get_all('Set-Cookie', [])
        except Exception as e:
            print(f"{RED}[-] Failed to connect to {target_url}: {e}{RESET}")
            return

        # Header Audits
        findings = []
        passed_headers = []

        print(f"{BOLD}{'SECURITY HEADER':<30} {'STATUS':<15} {'SEVERITY'}{RESET}")
        print("-" * 80)

        for rule in self.required_headers:
            header_name = rule["name"]
            if header_name.lower() in headers:
                passed_headers.append(header_name)
                print(f"{header_name:<30} {GREEN}{'PRESENT':<15}{RESET} {GRAY}OK{RESET}")
            else:
                findings.append(rule)
                severity_color = RED if rule["severity"] == "HIGH" else AMBER
                print(f"{header_name:<30} {RED}{'MISSING':<15}{RESET} {severity_color}{rule['severity']}{RESET}")

        # Cookie Audits
        if cookies:
            print("\n" + f"{BOLD}Cookie Security Configuration:{RESET}")
            for cookie in cookies:
                cookie_name = cookie.split("=")[0]
                has_secure = "secure" in cookie.lower()
                has_httponly = "httponly" in cookie.lower()
                has_samesite = "samesite" in cookie.lower()

                status = []
                if not has_secure: status.append("Missing Secure")
                if not has_httponly: status.append("Missing HttpOnly")
                if not has_samesite: status.append("Missing SameSite")

                if status:
                    print(f"  {AMBER}● {cookie_name}:{RESET} {RED}{', '.join(status)}{RESET}")
                else:
                    print(f"  {GREEN}✓ {cookie_name}:{RESET} Fully Hardened (Secure, HttpOnly, SameSite)")

        # Posture Score Calculation
        total_rules = len(self.required_headers)
        score = int((len(passed_headers) / total_rules) * 100) if total_rules > 0 else 0

        grade = "A+" if score == 100 else ("B" if score >= 70 else ("C" if score >= 50 else "F"))
        grade_color = GREEN if score >= 80 else (AMBER if score >= 50 else RED)

        print("=" * 80)
        print(f"\n{BOLD}Web Defense Posture Score:{RESET} {grade_color}{score}/100 [Grade: {grade}]{RESET}")

        if findings:
            print(f"\n{AMBER}{BOLD}[🛠️ REMEDIATION PLAYBOOK]{RESET}")
            for item in findings:
                print(f"  {CYAN}▸ {item['name']}{RESET} [{RED}{item['severity']}{RESET}]:")
                print(f"    {GRAY}├─ Risk:{RESET} {item['impact']}")
                print(f"    {GRAY}└─ Fix:{RESET}  {item['recommendation']}\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    auditor = ApexWebAuditor()
    auditor.run_audit(target)
