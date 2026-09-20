"""
Phishing Email Analyzer - Step 1
Parses a raw .eml file and extracts headers, auth results, and basic IOCs.

Usage:
    python analyze.py sample.eml
"""

import sys
import os
import re
import email
from email import policy
from email.parser import BytesParser

import tldextract


def load_email(filepath):
    """Load and parse a raw .eml file."""
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def get_body_parts(msg):
    """
    Return both the plain-text body and the raw (untouched) HTML body, if present.
    We keep HTML raw (tags intact) so link extraction can see href="..." values
    before anything strips the tags away.
    """
    plain_text = ""
    raw_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" and not plain_text:
                try:
                    plain_text = part.get_content()
                except Exception:
                    pass
            elif content_type == "text/html" and not raw_html:
                try:
                    raw_html = part.get_content()
                except Exception:
                    pass
    else:
        if msg.get_content_type() == "text/html":
            raw_html = msg.get_content()
        else:
            plain_text = msg.get_content()

    return plain_text, raw_html


def strip_html_tags(html):
    """Crude tag strip, for reading visible text / keyword scanning only.
    Do NOT use this before URL extraction - it destroys href attributes."""
    return re.sub("<[^<]+?>", " ", html)


def extract_urls(plain_text, raw_html):
    """
    Find URLs from both the plain-text body and the raw HTML body.
    Checks href="..." / src="..." attributes specifically, since a generic
    http(s):// scan misses nothing there, but stripping tags first would.
    """
    url_pattern = r"https?://[^\s\"'<>]+"
    urls = set(re.findall(url_pattern, plain_text))

    if raw_html:
        # Catches URLs sitting inside href="..." or src="..." attributes
        href_pattern = r'(?:href|src)\s*=\s*["\']?(https?://[^"\'\s>]+)'
        urls.update(re.findall(href_pattern, raw_html, re.IGNORECASE))
        # Also catch any bare URLs written directly in the HTML text
        urls.update(re.findall(url_pattern, raw_html))

    return list(urls)


def parse_auth_results(msg):
    """Pull SPF/DKIM/DMARC verdicts out of Authentication-Results header."""
    auth_header = msg.get("Authentication-Results", "")
    results = {"spf": None, "dkim": None, "dmarc": None}

    for key in results:
        match = re.search(rf"{key}=(\w+)", auth_header, re.IGNORECASE)
        if match:
            results[key] = match.group(1).lower()

    return results


def get_sender_ip(msg):
    """Grab the first (topmost/most recent) Received header and pull an IP out."""
    received_headers = msg.get_all("Received", [])
    if not received_headers:
        return None

    first = received_headers[0]
    ip_match = re.search(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?", first)
    return ip_match.group(1) if ip_match else None


def extract_domains(urls):
    """Extract root domains from a list of URLs."""
    domains = []
    for url in urls:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            domains.append(f"{ext.domain}.{ext.suffix}")
    return list(set(domains))


def check_from_reply_mismatch(msg):
    """Flag if From and Reply-To domains differ."""
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")

    if not reply_to:
        return False  # no reply-to set, nothing to compare

    from_match = re.search(r"@([\w.-]+)", from_addr)
    reply_match = re.search(r"@([\w.-]+)", reply_to)

    if from_match and reply_match:
        return from_match.group(1).lower() != reply_match.group(1).lower()
    return False


def check_urgency_language(text):
    """Simple keyword check for common phishing urgency phrases."""
    keywords = [
        "verify your account", "act now", "suspended", "urgent",
        "confirm your identity", "click here immediately", "unusual activity",
        "limited time", "your account will be closed", "update your payment",
    ]
    text_lower = text.lower()
    found = [kw for kw in keywords if kw in text_lower]
    return found


def get_attachments(msg):
    """List attachment filenames (does not open/extract contents)."""
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
    return attachments


RISKY_ATTACHMENT_EXTENSIONS = (
    ".exe", ".scr", ".js", ".vbs", ".vbe", ".bat", ".cmd", ".ps1",
    ".jar", ".msi", ".hta", ".wsf", ".lnk", ".iso", ".img",
    # Archive formats are a very common phishing delivery method,
    # since they often hide the real payload from basic mail filters
    ".zip", ".rar", ".7z", ".xz", ".gz", ".tar", ".cab", ".ace",
)


def calculate_risk_score(auth_results, mismatch, urgency_hits, domains, attachments):
    """Weighted scoring, tuned against real phishing/malspam samples."""
    score = 0
    reasons = []

    # SPF: fail is worse than softfail, but both are signals
    if auth_results["spf"] == "fail":
        score += 25
        reasons.append("SPF check failed")
    elif auth_results["spf"] == "softfail":
        score += 15
        reasons.append("SPF check soft-failed (server not fully authorized)")

    # DKIM: an outright fail is bad, but no signature at all is also suspicious
    if auth_results["dkim"] == "fail":
        score += 25
        reasons.append("DKIM check failed")
    elif auth_results["dkim"] in (None, "none"):
        score += 10
        reasons.append("No DKIM signature present")

    if auth_results["dmarc"] == "fail":
        score += 20
        reasons.append("DMARC check failed")

    if mismatch:
        score += 15
        reasons.append("From/Reply-To domain mismatch")

    if urgency_hits:
        score += 10
        reasons.append(f"Urgency language detected: {urgency_hits}")

    if any(d.split(".")[-1] in ("xyz", "tk", "top", "click") for d in domains):
        score += 15
        reasons.append("Suspicious top-level domain in links")

    # Attachments: presence alone is worth noting, risky extensions much more so
    if attachments:
        risky = [
            a for a in attachments
            if a.lower().endswith(RISKY_ATTACHMENT_EXTENSIONS)
        ]
        if risky:
            score += 30
            reasons.append(f"Risky attachment type(s): {risky}")
        else:
            score += 10
            reasons.append(f"Attachment present: {attachments}")

    if score >= 60:
        verdict = "HIGH RISK"
    elif score >= 30:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW RISK"

    return score, verdict, reasons


def analyze_file(filepath):
    """Run the full analysis on one .eml file. Returns (filepath, score, verdict) for summaries."""
    try:
        msg = load_email(filepath)
    except Exception as e:
        print(f"  [ERROR] Could not parse {filepath}: {e}")
        return (filepath, None, "PARSE ERROR")

    print("=" * 60)
    print(f"ANALYZING: {filepath}")
    print("=" * 60)

    # Basic headers
    print(f"\nFrom:      {msg.get('From')}")
    print(f"Reply-To:  {msg.get('Reply-To')}")
    print(f"Subject:   {msg.get('Subject')}")

    # Sender IP
    sender_ip = get_sender_ip(msg)
    print(f"\nSender IP (from Received header): {sender_ip}")

    # Auth results
    auth_results = parse_auth_results(msg)
    print(f"\nSPF:   {auth_results['spf']}")
    print(f"DKIM:  {auth_results['dkim']}")
    print(f"DMARC: {auth_results['dmarc']}")

    # From/Reply-To mismatch
    mismatch = check_from_reply_mismatch(msg)
    print(f"\nFrom/Reply-To mismatch: {mismatch}")

    # Body + URLs (now checks both plain-text and raw HTML, since links
    # often live inside href="..." attributes that used to get stripped away)
    plain_text, raw_html = get_body_parts(msg)
    urls = extract_urls(plain_text, raw_html)
    domains = extract_domains(urls)

    print(f"\nURLs found ({len(urls)}):")
    for u in urls:
        print(f"  - {u}")

    print(f"\nDomains extracted ({len(domains)}):")
    for d in domains:
        print(f"  - {d}")

    # Urgency language - check subject, plain text, and visible HTML text
    subject = msg.get("Subject", "") or ""
    visible_html_text = strip_html_tags(raw_html) if raw_html else ""
    urgency_hits = list(set(
        check_urgency_language(plain_text)
        + check_urgency_language(visible_html_text)
        + check_urgency_language(subject)
    ))
    print(f"\nUrgency phrases found: {urgency_hits}")

    # Attachments
    attachments = get_attachments(msg)
    print(f"\nAttachments found ({len(attachments)}):")
    for a in attachments:
        flag = " [RISKY TYPE]" if a.lower().endswith(RISKY_ATTACHMENT_EXTENSIONS) else ""
        print(f"  - {a}{flag}")

    # Risk score
    score, verdict, reasons = calculate_risk_score(
        auth_results, mismatch, urgency_hits, domains, attachments
    )

    print("\n" + "=" * 60)
    print(f"RISK SCORE: {score}/100  ->  {verdict}")
    print("Reasons:")
    for r in reasons:
        print(f"  - {r}")
    print("=" * 60)
    print()  # blank line to separate reports in batch mode

    return (filepath, score, verdict)


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Single file:  python analyze.py <email_file.eml>")
        print("  Whole folder: python analyze.py --folder <folder_path>")
        sys.exit(1)

    results = []

    if sys.argv[1] == "--folder":
        if len(sys.argv) < 3:
            print("Usage: python analyze.py --folder <folder_path>")
            sys.exit(1)

        folder = sys.argv[2]
        if not os.path.isdir(folder):
            print(f"Error: '{folder}' is not a valid folder.")
            sys.exit(1)

        eml_files = sorted(f for f in os.listdir(folder) if f.lower().endswith(".eml"))
        if not eml_files:
            print(f"No .eml files found in '{folder}'.")
            sys.exit(1)

        print(f"Found {len(eml_files)} .eml file(s) in '{folder}'. Analyzing each...\n")

        for filename in eml_files:
            full_path = os.path.join(folder, filename)
            results.append(analyze_file(full_path))

    else:
        filepath = sys.argv[1]
        results.append(analyze_file(filepath))

    # Summary table at the end - most useful when there's more than one result
    if len(results) > 1:
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        # Sort highest risk first so the worst offenders are easy to spot
        for filepath, score, verdict in sorted(
            results, key=lambda r: (r[1] is None, -(r[1] or 0))
        ):
            score_display = f"{score}/100" if score is not None else "N/A"
            print(f"  {verdict:12}  {score_display:8}  {os.path.basename(filepath)}")
        print("=" * 60)


if __name__ == "__main__":
    main()