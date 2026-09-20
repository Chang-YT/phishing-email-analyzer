# Phishing Email Analyzer

A Python tool that parses raw `.eml` files and produces a risk-scored report,
based on authentication results (SPF/DKIM/DMARC), sender/reply-to mismatches,
extracted URLs and domains, attachment risk, and urgency language. Supports
single-file analysis or batch scanning of an entire folder.

## Why I built this

I wanted hands-on practice with the kind of triage a SOC analyst does on
suspicious email: pulling apart headers, checking authentication results, and
identifying indicators of compromise (IOCs) without executing anything
dangerous. Rather than working from a tutorial dataset, I tested this against
real, recent phishing and malspam samples from
[malware-traffic-analysis.net](https://malware-traffic-analysis.net), a public
repository of real-world malicious traffic used by security researchers.

## Features

- Parses raw `.eml` files (headers, body, attachments) using Python's
  built-in `email` module — no external mail libraries required
- Extracts and evaluates SPF / DKIM / DMARC results from the
  `Authentication-Results` header
- Flags From / Reply-To domain mismatches
- Extracts URLs from **both** plain-text and HTML bodies, including links
  hidden inside `href="..."` / `src="..."` attributes (see *Bugs found and
  fixed*, below)
- Extracts root domains from found URLs (`tldextract`)
- Lists email attachments and flags risky file types (executables, scripts,
  and archive formats like `.zip` / `.7z` / `.xz`, which are a common
  malware delivery method)
- Scans subject line and body text for urgency/pressure language
- Produces a weighted 0–100 risk score with a plain-language explanation of
  every point awarded
- Batch mode: point it at a folder and get a full report per email plus a
  ranked summary table

## Usage

```bash
# Single file
python analyze.py samples/sample.eml

# Whole folder
python analyze.py --folder samples
```

### Setup

```bash
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
```

## Example output

```
============================================================
ANALYZING: 2025-05-12-email-with-malware-attachment-0845-UTC.eml
============================================================
From:      Sedra Al Jundi <cert@etsdc.com>
Subject:   RE: Urgent: Confirmation Required for Invoice & Down Payment Details
SPF:   softfail   DKIM:  none   DMARC: fail
Urgency phrases found: ['urgent']
Attachments found: ['etsdc.jpg', 'invoice_10988.xz [RISKY TYPE]']
------------------------------------------------------------
RISK SCORE: 85/100  ->  HIGH RISK
```

## Bugs found and fixed during testing

Testing against real samples (rather than synthetic test data) surfaced two
real defects in the first version of the URL extractor:

1. **HTML tag-stripping was deleting links before they could be found.**
   The original body parser stripped `<tags>` with a regex *before* searching
   for URLs. Since a real link lives inside the tag itself
   (`<a href="http://evil.com">`), stripping the tag deleted the URL along
   with it — the extractor was left with only the visible link text, never
   the actual destination. Fixed by extracting `href=` / `src=` values from
   the **raw** HTML first, and only stripping tags afterward for keyword
   scanning.

2. **Plain-text was preferred over HTML even when it lacked the payload.**
   Some phishing emails put the real malicious link only in the HTML version
   (as a styled button or image), while the plain-text version is empty,
   generic, or contains a decoy. The original script only checked
   `text/plain` if it existed at all, silently ignoring the HTML version's
   link. Fixed by checking both parts and combining results.

This is a good example of why testing tools like this against **real, messy
samples** — not just clean synthetic examples — matters: both bugs produced
zero errors, zero crashes, and confidently wrong (falsely low) results.

## Key finding: authentication passing does not mean the sender is trustworthy

The `2026-01-09 VIP Recovery` sample (a real malspam campaign, confirmed
malicious) passed **SPF, DKIM, and DMARC** entirely. This scored it only
30/100 (MEDIUM) on authentication alone — because the attacker owns and
correctly configures the domain they're spoofing from. Authentication
checks confirm a sender is who their own DNS says they are; they do **not**
confirm the sender is safe. In this tool, it was the attachment-risk check
(a `.7z` archive) — not the authentication check — that pushed the score
into a meaningful risk range. This mirrors a real lesson in phishing
detection: no single signal is sufficient on its own.

## Known limitations

- **Urgency-language detection is English-only.** A real Japanese phishing
  sample (brand impersonation of Yodobashi Camera, malicious `.cn` domain)
  scored artificially low (10/100) because the keyword list doesn't cover
  Japanese phrasing. This is a known gap, not a bug — see *Roadmap*.
- **No live reputation checking.** Domains and URLs are extracted and
  flagged for suspicious TLDs, but not yet checked against threat
  intelligence sources like VirusTotal or AbuseIPDB.
- **Attachment risk is based on file extension only.** The tool does not
  open, execute, or scan attachment contents — it flags risk by filename/
  extension alone, which a sufficiently disguised file could evade.
- **Filename spoofing (double extensions, icon mismatch) is not detected.**

## Roadmap

- [ ] VirusTotal / AbuseIPDB integration for domain and IP reputation scoring
- [ ] Multi-language urgency/social-engineering keyword sets
- [ ] JSON/CSV export of results for integration with other tools
- [ ] Optional attachment hash extraction (SHA256) for IOC reporting without
      opening the file

## A note on sample data

This tool was tested against real phishing and malspam samples sourced from
[malware-traffic-analysis.net](https://malware-traffic-analysis.net), a
well-known public resource used by security researchers and maintained by
Brady Duncan. **Raw email samples are intentionally not included in this
repository** — several contain links to live malicious infrastructure or
sit alongside real malware attachments, and redistributing them is not
appropriate for a public GitHub repo. To reproduce these results, download
samples directly from the source site (each zip is password-protected per
their standard convention) and place the extracted `.eml` files into a local
`samples/` folder in this project — already excluded via `.gitignore`.

**Handling note:** never click links or open attachments from these emails
outside an isolated, disposable environment. This tool only reads text and
headers — it never fetches URLs or opens attachment contents.

## Tech stack

- Python 3.10+
- `email` (standard library) — MIME parsing
- `tldextract` — accurate root-domain extraction
- `requests` — reserved for planned threat-intel API integration

## Author's note

Built as a hands-on SOC/security-analyst portfolio project, alongside a
companion IOC/threat-intelligence enrichment tool.