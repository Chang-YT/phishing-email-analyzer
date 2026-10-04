Phishing Email Analyzer - supports single-file analysis / batch scanning

Python cmd tool that accept raw `.eml` files and generate a risk-scored report
based on authentication results, sender/reply-to mismatches, extracted URLs and domains, attachment risk, and urgency language


# dataset source
**real-world email samples not included in this repository** 
download samples directly from the website [malware-traffic-analysis.net](https://malware-traffic-analysis.net) a public repository providing real-world malicious traffic
after download, place the extracted `.eml` files into the local `samples/` folder in this project

*note that:* never click on link or open attachments from a real-world malicious email you get !!! This tool only read text and headers and will never fetches URLs or opens attachment contents
SOOOOOOO DO NOT OPEN THEM MANUALLY X_X

# setup
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate   # macOS/Linux
pip install -r requirements.txt


# single file analyze
python analyze.py samples/sample.eml

# entire folder analyze
python analyze.py --folder samples


## features

- parses raw `.eml` files (headers, body, attachments) using Python built-in `email` module
- extracts + evaluates SPF / DKIM / DMARC results in the `Authentication-Results` header
- flag out the From / Reply-To domain mismatches
- extract URLs from plain-text and HTML body | including links hidden inside `href="..."` / `src="..."` attributes (see *bugs and fixes*)
- extracts root domains from found URLs (`tldextract`)
- list out email attachments and flags risky file types (executables, scripts, archive `.zip` / `.7z` / `.xz`)
- subject line and body text are scanned for urgency/pressure language
- final 0–100 risk score with explanation
- batch analyze will generate report per email with one ranking summary table


# bugs and fixes

1. HTML tag-stripping delete links before it got deteced

   real link lives inside the tag (`<a href="http://evil.com">`)
   stripping the tag will also delte the URL
   leaving only the visible link text with no actual destination
   
   **Fixed by extracting `href=` / `src=` values from the raw HTML first and strip tags for keyword scanning only after that

2. plain-text choosen over HTML version even when it's lack of info

   some phishing email only put the real malicious link in the HTML like a styled button or image
   while the plain-text message is empty, general or might comes with decoy
   The script in first version will only check if `text/plain` exist ignoring link hidden in HTML

   **Fixed by checking both `text/plain` and HTML


# real case senario - authentication doesnt mean its safe

the "2026-01-09 VIP Recovery" phishing email passed SPF, DKIM, and DMARC in the system, looking legitimate
but those will only check if the sender controls the domain, it will not tell if the domain itself is trustworthy
even with a common malware delivery file .7z attached in that email, which should be enough for a high score flag, 
the final score for this sample is only 30/100

after this case we know that-- a verified sender doesnt mean that its a safe sender, authentication checks itself cant make a accurate phishing detection system

# limitation

1 language 
 a Japanese phishing sample (brand impersonation of Yodobashi Camera, malicious `.cn` domain) showed low score (10/100) because the keyword list doesn't cover Japanese phrasing

2 static checking
 domains and URLs were flagged as suspicious, but not yet get check on threat intelligence sources like VirusTotal or AbuseIPDB
 
3 more detection signals
single security check is not enough for accurate phishing detection
adding in multiple signals, like the sender’s reputation, email content, links, attachments, and more

4 unwrap_redirect function limitaion
only unwraps the three specific formats(Google redirect wrapper,Cisco Secure Web Gateway, googleusercontent proxy image)
will not check on other possible redirect service on the internet