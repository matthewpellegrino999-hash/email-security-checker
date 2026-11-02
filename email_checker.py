#!/usr/bin/env python3
"""
Email Security Checker
Checks a domain's SPF, DKIM, and DMARC records and explains how to fix problems.

Usage:
    python3 email_checker.py example.org
    python3 email_checker.py example.org --selector myselector
    python3 email_checker.py example.org --html report.html

Uses only the Python standard library. DNS lookups go through Cloudflare's
public DNS-over-HTTPS service, so it works the same on Mac, Windows, and Linux.
"""

import argparse
import html
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
from datetime import datetime

DOH_URL = "https://cloudflare-dns.com/dns-query"

# Some Python installs (e.g. python.org on macOS) ship without CA certificates.
# Fall back to the operating system's bundle so HTTPS stays fully verified.
SSL_CONTEXT = ssl.create_default_context()
if not SSL_CONTEXT.cert_store_stats()["x509_ca"] and os.path.exists("/etc/ssl/cert.pem"):
    SSL_CONTEXT.load_verify_locations("/etc/ssl/cert.pem")

# Common DKIM selectors used by popular email providers.
COMMON_DKIM_SELECTORS = [
    "google", "20230601", "20210112",  # Google Workspace
    "s2048", "s1024",                  # Yahoo / AOL
    "selector1", "selector2",    # Microsoft 365
    "default", "dkim", "mail", "k1", "k2", "s1", "s2",
    "smtp", "mandrill", "mxvault", "everlytickey1", "zoho",
]

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"


# ---------------------------------------------------------------- DNS lookups

def dns_query(name, record_type):
    """Return a list of answer strings for a DNS query (empty list if none)."""
    params = urllib.parse.urlencode({"name": name, "type": record_type})
    req = urllib.request.Request(
        f"{DOH_URL}?{params}", headers={"Accept": "application/dns-json"}
    )
    with urllib.request.urlopen(req, timeout=10, context=SSL_CONTEXT) as resp:
        data = json.load(resp)
    type_codes = {"TXT": 16, "MX": 15, "CNAME": 5}
    wanted = type_codes[record_type]
    answers = []
    for answer in data.get("Answer", []):
        if answer.get("type") != wanted:
            continue
        value = answer["data"]
        if record_type == "TXT" and value.startswith('"'):
            # Long TXT records come back as several quoted chunks; join them.
            value = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', value))
        answers.append(value.strip())
    return answers


def domain_exists(domain):
    """False if DNS says the domain does not exist (NXDOMAIN)."""
    params = urllib.parse.urlencode({"name": domain, "type": "SOA"})
    req = urllib.request.Request(
        f"{DOH_URL}?{params}", headers={"Accept": "application/dns-json"}
    )
    with urllib.request.urlopen(req, timeout=10, context=SSL_CONTEXT) as resp:
        return json.load(resp).get("Status") != 3


def get_txt(name):
    return dns_query(name, "TXT")


# --------------------------------------------------------------------- checks

def check_mx(domain):
    records = dns_query(domain, "MX")
    if not records:
        return [(WARN, "No MX records found. This domain can't receive email. "
                       "If it never sends email either, publish 'v=spf1 -all' and "
                       "a DMARC 'p=reject' record so nobody can spoof it.")], records
    if records == ["0 ."]:
        return [(PASS, "Null MX record: this domain declares that it does not accept "
                       "email. Good practice for domains that don't use email.")], records
    return [(INFO, f"Mail servers: {', '.join(records)}")], records


def check_spf(domain):
    results = []
    spf = [r for r in get_txt(domain) if r.lower().startswith("v=spf1")]

    if not spf:
        results.append((FAIL, "No SPF record found. Anyone can send email "
                              "pretending to be this domain."))
        results.append((INFO, "Fix: add a TXT record at the root of your domain, e.g. "
                              "Google Workspace: 'v=spf1 include:_spf.google.com ~all'  "
                              "Microsoft 365: 'v=spf1 include:spf.protection.outlook.com -all'"))
        return results, None

    if len(spf) > 1:
        results.append((FAIL, f"Found {len(spf)} SPF records. Only ONE is allowed, "
                              "otherwise SPF breaks. Merge them into a single record."))

    record = spf[0]
    results.append((INFO, f"Record: {record}"))
    terms = record.lower().split()

    # A 'redirect=' hands the rest of the rules to another SPF record; follow it
    # (up to 3 hops) so the 'all' ending is read from the record actually used.
    policy_terms = terms
    for _ in range(3):
        if any(t.lstrip("+-~?") == "all" for t in policy_terms):
            break
        target = next((t.split("=", 1)[1] for t in policy_terms
                       if t.startswith("redirect=")), None)
        if not target:
            break
        redirected = [r for r in get_txt(target) if r.lower().startswith("v=spf1")]
        if not redirected:
            results.append((FAIL, f"Redirects to '{target}', but no SPF record exists there."))
            break
        results.append((INFO, f"Redirects to {target}: {redirected[0]}"))
        policy_terms = redirected[0].lower().split()

    # How strict is the policy at the end?
    all_term = next((t for t in policy_terms if t.lstrip("+-~?") == "all"), None)
    if all_term == "-all":
        results.append((PASS, "Ends in '-all' (hard fail): unauthorized senders are rejected."))
    elif all_term == "~all":
        results.append((PASS, "Ends in '~all' (soft fail): unauthorized senders are "
                              "flagged. Fine when paired with a strict DMARC policy."))
    elif all_term == "?all":
        results.append((FAIL, "Ends in '?all' (neutral): SPF takes no position on "
                              "unauthorized senders. Change it to '~all' or '-all'."))
    elif all_term in ("+all", "all"):
        results.append((FAIL, f"Ends in '{all_term}', which lets ANY server send as you. "
                              "Change it to '~all' or '-all'."))
    else:
        results.append((WARN, "No 'all' mechanism at the end. Add '~all' or '-all'."))

    # SPF allows at most 10 DNS lookups.
    lookup_terms = [t for t in terms
                    if t.lstrip("+-~?").split(":")[0].split("=")[0]
                    in ("include", "a", "mx", "ptr", "exists", "redirect")]
    count = len(lookup_terms)
    if count > 10:
        results.append((FAIL, f"{count} DNS lookups at the top level (limit is 10). "
                              "SPF will fail. Remove unused includes."))
    elif count >= 8:
        results.append((WARN, f"{count} DNS lookups at the top level, close to the "
                              "limit of 10 (nested includes count too)."))
    else:
        results.append((PASS, f"{count} DNS lookup(s) at the top level (limit is 10)."))

    if any(t.lstrip("+-~?").startswith("ptr") for t in terms + policy_terms):
        results.append((WARN, "Uses the 'ptr' mechanism, which is deprecated. Remove it."))

    return results, record


def check_dmarc(domain):
    results = []
    dmarc = [r for r in get_txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]

    if not dmarc:
        results.append((FAIL, "No DMARC record found. Receiving servers have no "
                              "instructions for handling spoofed email."))
        results.append((INFO, f"Fix: add a TXT record named '_dmarc' with: "
                              f"'v=DMARC1; p=none; rua=mailto:dmarc@{domain}' to start "
                              "monitoring, then move to p=quarantine and p=reject."))
        return results, None

    if len(dmarc) > 1:
        results.append((FAIL, "More than one DMARC record. Only one is allowed."))

    record = dmarc[0]
    results.append((INFO, f"Record: {record}"))
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()

    policy = tags.get("p", "").lower()
    if policy == "reject":
        results.append((PASS, "Policy is 'reject': spoofed email is blocked. Best setting."))
    elif policy == "quarantine":
        results.append((PASS, "Policy is 'quarantine': spoofed email goes to spam. "
                              "Consider moving to 'reject' once reports look clean."))
    elif policy == "none":
        results.append((WARN, "Policy is 'none': monitoring only, spoofed email is still "
                              "delivered. Move to 'quarantine' after reviewing reports."))
    else:
        results.append((FAIL, "Missing or invalid 'p=' policy tag."))

    pct = tags.get("pct")
    if pct and pct != "100":
        results.append((WARN, f"pct={pct}: the policy only applies to {pct}% of mail."))

    if "rua" in tags:
        results.append((PASS, f"Aggregate reports are sent to: {tags['rua']}"))
    else:
        results.append((WARN, "No 'rua=' tag, so you get no reports about who is "
                              "sending email as your domain. Add 'rua=mailto:you@yourdomain'."))

    return results, record


def check_dkim(domain, extra_selectors=None, spf_record=None):
    results = []
    if spf_record and spf_record.lower().split() == ["v=spf1", "-all"]:
        results.append((PASS, "SPF says this domain sends no email at all, so DKIM "
                              "signing is not needed."))
        return results, []
    selectors = list(extra_selectors or []) + COMMON_DKIM_SELECTORS
    found = []
    for selector in dict.fromkeys(selectors):  # de-duplicate, keep order
        name = f"{selector}._domainkey.{domain}"
        records = [r for r in get_txt(name) if "p=" in r.lower() or "v=dkim1" in r.lower()]
        if not records:
            # Microsoft 365 publishes DKIM as a CNAME pointing to its own record.
            if dns_query(name, "CNAME"):
                records = get_txt(name)
        if records:
            found.append((selector, records[0]))

    if not found:
        results.append((WARN, "No DKIM key found under common selector names. DKIM may "
                              "still be set up with a custom selector; check a real email's "
                              "headers for 's=' in the DKIM-Signature line and re-run with "
                              "--selector."))
        results.append((INFO, "Fix: Google Workspace: Admin console > Apps > Gmail > "
                              "Authenticate email. Microsoft 365: Defender portal > Email "
                              "authentication settings > DKIM."))
        return results, found

    revoked = []
    for selector, record in found:
        compact = record.replace(" ", "")
        if "p=;" in compact or compact.endswith("p="):
            revoked.append(selector)
        else:
            results.append((PASS, f"DKIM key found for selector '{selector}'."))
    if revoked and not results:
        results.append((WARN, "Only empty (revoked) DKIM keys were found. Publish an "
                              "active key from your email provider."))
    elif revoked:
        results.append((INFO, f"Revoked keys also present for: {', '.join(revoked)}"))
    return results, found


# -------------------------------------------------------------------- output

def grade(sections):
    statuses = [s for _, items in sections for s, _ in items]
    fails, warns = statuses.count(FAIL), statuses.count(WARN)
    if fails == 0 and warns == 0:
        return "A", "Excellent. This domain is well protected against spoofing."
    if fails == 0 and warns <= 2:
        return "B", "Good, with a few improvements recommended."
    if fails <= 1:
        return "C", "Partially protected. Review the warnings and failures below."
    if fails <= 3:
        return "D", "Weak. This domain is easy to spoof."
    return "F", "Unprotected. Anyone can send email pretending to be this domain."


COLORS = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m", INFO: "\033[36m"}
RESET = "\033[0m"


def print_report(domain, sections, use_color=True):
    letter, summary = grade(sections)
    print(f"\nEmail Security Report for {domain}")
    print("=" * (26 + len(domain)))
    for title, items in sections:
        print(f"\n{title}")
        print("-" * len(title))
        for status, message in items:
            tag = f"[{status}]"
            if use_color:
                tag = f"{COLORS[status]}{tag}{RESET}"
            print(f"  {tag} {message}")
    print(f"\nOverall grade: {letter}  {summary}\n")


def write_html(domain, sections, path):
    letter, summary = grade(sections)
    badge = {PASS: "#1a7f37", WARN: "#9a6700", FAIL: "#cf222e", INFO: "#0969da"}
    rows = []
    for title, items in sections:
        rows.append(f"<h2>{html.escape(title)}</h2><ul>")
        for status, message in items:
            rows.append(
                f'<li><span class="tag" style="background:{badge[status]}">{status}</span>'
                f"{html.escape(message)}</li>"
            )
        rows.append("</ul>")
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Email Security Report: {html.escape(domain)}</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 820px;
        margin: 40px auto; padding: 0 20px; color: #1f2328; line-height: 1.5; }}
 .grade {{ font-size: 48px; font-weight: 700; }}
 ul {{ list-style: none; padding: 0; }}
 li {{ margin: 8px 0; }}
 .tag {{ color: #fff; border-radius: 4px; padding: 1px 8px; margin-right: 10px;
        font-size: 12px; font-weight: 600; }}
 .meta {{ color: #656d76; font-size: 14px; }}
</style></head><body>
<h1>Email Security Report: {html.escape(domain)}</h1>
<p class="meta">Generated {datetime.now():%B %d, %Y at %I:%M %p}</p>
<p><span class="grade">{letter}</span> {html.escape(summary)}</p>
{''.join(rows)}
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


# ---------------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(description="Check a domain's SPF, DKIM, and DMARC setup.")
    parser.add_argument("domain", nargs="?",
                        help="domain to check, e.g. example.org (asked for if left out)")
    parser.add_argument("--selector", action="append", default=[],
                        help="extra DKIM selector to try (can be repeated)")
    parser.add_argument("--html", metavar="FILE", help="also save an HTML report")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    args = parser.parse_args()

    # No domain given (e.g. run from IDLE with F5): ask for one.
    if not args.domain:
        args.domain = input("Enter a domain to check (e.g. redcross.org): ")
        if not args.domain.strip():
            print("No domain entered.")
            sys.exit(1)
        if not args.html and input("Save an HTML report too? (y/n): ").strip().lower().startswith("y"):
            args.html = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.html")

    domain = args.domain.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]

    try:
        if not domain_exists(domain):
            print(f"Error: '{domain}' does not exist in DNS. Check the spelling.")
            sys.exit(1)
        spf_results, spf_record = check_spf(domain)
        sections = [
            ("Mail Servers (MX)", check_mx(domain)[0]),
            ("SPF (who is allowed to send)", spf_results),
            ("DKIM (email signatures)", check_dkim(domain, args.selector, spf_record)[0]),
            ("DMARC (what to do with spoofed mail)", check_dmarc(domain)[0]),
        ]
    except OSError as e:
        print(f"Error: could not reach the DNS service ({e}). Check your internet connection.")
        sys.exit(1)

    print_report(domain, sections, use_color=not args.no_color and sys.stdout.isatty())
    if args.html:
        write_html(domain, sections, args.html)
        print(f"HTML report saved to {args.html}\n")


if __name__ == "__main__":
    main()
