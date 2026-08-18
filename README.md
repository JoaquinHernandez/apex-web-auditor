# apex-web-auditor

# 🌐 Apex-WebAudit: Interactive Web Defense & OWASP Posture Scanner

A lightweight, zero-dependency web application security auditing tool that inspects HTTP response headers, cookie flags, and transport encryption against standard **OWASP Top 10** defensive baselines.

---

## ✨ Key Capabilities
- **Security Header Auditing**: Verifies critical protections including `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), and `X-Frame-Options`.
- **Cookie Hardening Checks**: Validates `Secure`, `HttpOnly`, and `SameSite` flags on session identifiers.
- **Automated Scorecard & Remediation**: Generates a defensive grade (`A+` to `F`) along with actionable remediation directives.
- **Zero Dependencies**: Pure Python standard library implementation.

---

## 🚀 Quick Start

### 1. Audit Default Target
```bash
python3 apex_scanner.py


python3 apex_scanner.py [https://yourwebsite.com](https://yourwebsite.com)
