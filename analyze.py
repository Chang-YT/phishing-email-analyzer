import sys
import os
import re
import hashlib
import email
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse, parse_qs, unquote

import tldextract


def load_email(filepath):
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def get_body_parts(msg):
 
    #Return plain-text body and the raw HTML body keeping tags in HTML so link extraction can see href="..." values

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
    #Do NOT use this before URL extraction - it will destroy the href attribute!!
    return re.sub("<[^<]+?>", " ", html)


def extract_urls(plain_text, raw_html):
    #find URLs from both plain-text body and raw HTML body

    url_pattern = r"https?://[^\s\"'<>]+"
    urls = set(re.findall(url_pattern, plain_text))

    if raw_html:
        # catch URL inside href="..." src="..." 
        href_pattern = r'(?:href|src)\s*=\s*["\']?(https?://[^"\'\s>]+)'
        urls.update(re.findall(href_pattern, raw_html, re.IGNORECASE))
        # catch URs written directly in the HTML text
        urls.update(re.findall(url_pattern, raw_html))

    return list(urls)


def parse_auth_results(msg):
    #SPF/DKIM/DMARC
    auth_header = msg.get("Authentication-Results", "")
    results = {"spf": None, "dkim": None, "dmarc": None}

    for key in results:
        match = re.search(rf"{key}=(\w+)", auth_header, re.IGNORECASE)
        if match:
            results[key] = match.group(1).lower()

    return results


def get_sender_ip(msg):
    received_headers = msg.get_all("Received", [])
    if not received_headers:
        return None

    first = received_headers[0]
    ip_match = re.search(r"\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?", first)
    return ip_match.group(1) if ip_match else None


def extract_domains(urls):
    # root domains
    domains = []
    for url in urls:
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            domains.append(f"{ext.domain}.{ext.suffix}")
    return list(set(domains))


def unwrap_redirect(url):
    #try to reveal the real destination behind a known wrapper/redirect URL
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()

    # Google redirect wrapper
    if "google.com" in netloc and parsed.path == "/url":
        qs = parse_qs(parsed.query)
        if "q" in qs:
            return unquote(qs["q"][0])

    # Cisco Secure Web Gateway
    if "secure-web.cisco.com" in netloc:
        path_parts = parsed.path.strip("/").split("/")
        if path_parts:
            candidate = unquote(unquote(path_parts[-1]))
            if candidate.startswith("http"):
                return candidate

    # googleusercontent proxy image
    if "googleusercontent.com" in netloc and "#http" in url:
        return url.split("#", 1)[1]

    return None


def unwrap_all_urls(urls):
    # return list of original and unwrapped URLs
    all_urls = set(urls)
    unwrapped_pairs = []

    for url in urls:
        real = unwrap_redirect(url)
        if real and real not in all_urls:
            all_urls.add(real)
            unwrapped_pairs.append((url, real))

    return list(all_urls), unwrapped_pairs


def check_from_reply_mismatch(msg):
    # flag if From and Reply-To domains diff
    from_addr = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")

    if not reply_to:
        return False  # no reply-to set

    from_match = re.search(r"@([\w.-]+)", from_addr)
    reply_match = re.search(r"@([\w.-]+)", reply_to)

    if from_match and reply_match:
        return from_match.group(1).lower() != reply_match.group(1).lower()
    return False


def check_urgency_language(text):
    #common phishing urgency phrase
    keywords = [
        "verify your account", "act now", "suspended", "urgent",
        "confirm your identity", "click here immediately", "unusual activity",
        "limited time", "your account will be closed", "update your payment",
    ]
    text_lower = text.lower()
    found = [kw for kw in keywords if kw in text_lower]
    return found


def get_attachments(msg):
    # list out attached file names
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
    return attachments


def get_attachment_hashes(msg):
    # calculate a SHA-256 hash for every email attachment, report for IOC (Indicator of Compromise)
    results = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if not filename:
                continue
            try:
                payload = part.get_payload(decode=True)
                sha256 = hashlib.sha256(payload).hexdigest() if payload else None
            except Exception:
                sha256 = None
            results.append({"filename": filename, "sha256": sha256})
    return results


RISKY_ATTACHMENT_EXTENSIONS = (
    ".exe", ".scr", ".js", ".vbs", ".vbe", ".bat", ".cmd", ".ps1",
    ".jar", ".msi", ".hta", ".wsf", ".lnk", ".iso", ".img",
    ".zip", ".rar", ".7z", ".xz", ".gz", ".tar", ".cab", ".ace",
    # archive files can hide payload from mail filter
)


def calculate_risk_score(auth_results, mismatch, urgency_hits, domains, attachments):
    score = 0
    reasons = []

    # SPF: server sending the email is authorized or not
    if auth_results["spf"] == "fail":
        score += 25
        reasons.append("SPF check failed")
    elif auth_results["spf"] == "softfail":
        score += 15
        reasons.append("SPF check soft-failed (server not fully authorized)")

    # DKIM: message was authorized by the domain and wasn't modified? no signature is also suspicious 
    if auth_results["dkim"] == "fail":
        score += 25
        reasons.append("DKIM check failed")
    elif auth_results["dkim"] in (None, "none"):
        score += 10
        reasons.append("No DKIM signature present")

    #DMARC: domain in the visible 'From' address same with results SPF/DKIM?
    if auth_results["dmarc"] == "fail":
        score += 20
        reasons.append("DMARC check failed")

    if mismatch:
        score += 15
        reasons.append("From/Reply-To domain mismatch")

    if urgency_hits:
        score += 10
        reasons.append(f"Urgency language detected: {urgency_hits}")

    # check top-level domain (TLD)
    if any(d.split(".")[-1] in ("xyz", "tk", "top", "click") for d in domains):
        score += 15
        reasons.append("Suspicious top-level domain in links")

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
    #full analyse
    try:
        msg = load_email(filepath)
    except Exception as e:
        print(f"  [ERROR] Could not parse {filepath}: {e}")
        return (filepath, None, "PARSE ERROR")

    print("=" * 60)
    print(f"ANALYZING: {filepath}")
    print("=" * 60)

    # headers
    print(f"\nFrom:      {msg.get('From')}")
    print(f"Reply-To:  {msg.get('Reply-To')}")
    print(f"Subject:   {msg.get('Subject')}")

    # sender's IP
    sender_ip = get_sender_ip(msg)
    print(f"\nSender IP (from Received header): {sender_ip}")

    # auth results
    auth_results = parse_auth_results(msg)
    print(f"\nSPF:   {auth_results['spf']}")
    print(f"DKIM:  {auth_results['dkim']}")
    print(f"DMARC: {auth_results['dmarc']}")

    # From/Reply-To mismatch
    mismatch = check_from_reply_mismatch(msg)
    print(f"\nFrom/Reply-To mismatch: {mismatch}")

    plain_text, raw_html = get_body_parts(msg)
    urls = extract_urls(plain_text, raw_html)

    # real destination
    all_urls, unwrapped_pairs = unwrap_all_urls(urls)
    domains = extract_domains(all_urls)

    print(f"\nURLs found ({len(urls)}):")
    for u in urls:
        print(f"  - {u}")

    if unwrapped_pairs:
        print(f"\nRedirects unwrapped ({len(unwrapped_pairs)}):")
        for original, real in unwrapped_pairs:
            print(f"  - {original[:70]}...")
            print(f"    -> real destination: {real}")

    print(f"\nDomains extracted ({len(domains)}):")
    for d in domains:
        print(f"  - {d}")

    # urgency language check
    subject = msg.get("Subject", "") or ""
    visible_html_text = strip_html_tags(raw_html) if raw_html else ""
    urgency_hits = list(set(
        check_urgency_language(plain_text)
        + check_urgency_language(visible_html_text)
        + check_urgency_language(subject)
    ))
    print(f"\nUrgency phrases found: {urgency_hits}")

    # attachment
    attachments = get_attachments(msg)
    attachment_hashes = get_attachment_hashes(msg)
    print(f"\nAttachments found ({len(attachments)}):")
    for a in attachment_hashes:
        flag = " [RISKY TYPE]" if a["filename"].lower().endswith(RISKY_ATTACHMENT_EXTENSIONS) else ""
        print(f"  - {a['filename']}{flag}")
        print(f"    SHA256: {a['sha256']}")

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
    print()  # blank line - separate report in batch search

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

    # Summary table for batch search
    if len(results) > 1:
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        # higest risk first
        for filepath, score, verdict in sorted(
            results, key=lambda r: (r[1] is None, -(r[1] or 0))
        ):
            score_display = f"{score}/100" if score is not None else "N/A"
            print(f"  {verdict:12}  {score_display:8}  {os.path.basename(filepath)}")
        print("=" * 60)


if __name__ == "__main__":
    main()