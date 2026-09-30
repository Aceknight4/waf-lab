# Web Application Firewall Lab

A Web Application Firewall built from scratch in Python/Flask, placed in front of a deliberately vulnerable web app (DVWA), and wired into an existing Wazuh SIEM  proving detection **and** prevention, not just observation.

This is a companion piece to my [Honeypot + SIEM lab](../honeypot-cowrie-lab): where that project shows a system that *lures and watches* attackers, this one shows a system that actively *blocks* them.

![Architecture diagram](diagrams/waf-architecture.svg)

## What it does

A transparent reverse proxy sits on port 80, in front of DVWA (port 8080). Every request is inspected before it's allowed through:

- **Signature-based detection** for SQL Injection, XSS, and Path Traversal / LFI, using regex rules against the URL-decoded path, query string, and body
- **Rate limiting**  a per-IP sliding window (30 requests / 10 seconds) that blocks volume-based abuse (brute force, scripted hammering) that signature rules can't see, since the content of each request is clean
- **Structured JSON logging** of every block event (rule fired, matched text, source IP, path)
- **Live SIEM integration**  block events are forwarded to Wazuh, decoded automatically, and matched against custom rules that produce human-readable, correctly-severity-scored alerts

Clean traffic is forwarded to DVWA unchanged and the response passed straight back. Nothing is blocked unless it matches an actual rule.

## Results

| Attack type | Unprotected | Behind the WAF |
|---|---|---|
| SQL Injection (`' OR '1'='1`) | Full user table dumped | `403 Forbidden` |
| Reflected XSS (`<script>alert('XSS')</script>`) | JavaScript executes | `403 Forbidden` |
| Path Traversal / LFI (`../../../../etc/passwd`) | File contents disclosed | `403 Forbidden` |
| Rapid-fire requests (35 in <1s) | All succeed | First 30 succeed, rest `429 Too Many Requests` |

Every block is also picked up by Wazuh and appears in Threat Hunting with a proper description and severity level — e.g. *"WAF blocked a SQL Injection attempt from 192.168.100.20"* at rule level 10, not just a raw log line.

## A real bug, found and fixed

The first working version of the SQLi rule quietly failed to catch its own test payload. The cause: Flask's `request.query_string` returns the **raw, still-percent-encoded** text exactly as sent on the wire — so `=` arrived as `%3D`, not `=`, and the regex never matched. This is a well-known real-world WAF bypass technique: encode the payload, slip past a filter that doesn't decode first.

**Fix:** run the combined path/query/body through `urllib.parse.unquote_plus()` *before* pattern matching, catching both `%XX` sequences and `+`-encoded spaces. Verified against the exact captured payload before redeploying — see `app.py`, function `inspect()`.

## Architecture

```
Kali (attacker) → Flask WAF Proxy :80 → [clean] → DVWA (Docker) :8080
                         │
                    [malicious]
                         │
                    403 / 429 response
                         │
                  waf_blocks.log (JSON)
                         │
                  Wazuh Agent "waf-lab"
                         │
                  Wazuh Manager (custom rules 100110–100114)
                         │
                  Threat Hunting alert
```

All on the same isolated host-only lab network (`192.168.100.0/24`) shared with the honeypot/SIEM project.

## Tech stack

- **Python 3 / Flask** — reverse proxy and detection logic
- **Docker** — DVWA target application
- **Wazuh 4.14** — SIEM, log ingestion, alerting (manager + dashboard shared with the honeypot lab)
- **Kali Linux** — attack simulation

## Repo contents

```
.
├── README.md
├── app.py                    # the WAF itself
├── requirements.txt
├── diagrams/
│   └── waf-architecture.svg
├── wazuh/
│   └── waf-rules.xml         # custom detection rules (Wazuh manager side)
└── screenshots/
    ├── 01-baseline-sqli-unprotected.png
    ├── 02-waf-blocking-sqli.png
    ├── 03-baseline-xss-unprotected.png
    ├── 04-waf-blocking-xss.png
    ├── 05-baseline-lfi-unprotected.png
    ├── 06-waf-blocking-lfi.png
    ├── 07-waf-rate-limiting.png
    └── 08-waf-wazuh-alert.png
```

## Running it locally

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# point BACKEND in app.py at your own vulnerable target, then:
sudo venv/bin/python app.py
```

For the Wazuh side: set the agent's `ossec.conf` to monitor `waf_blocks.log` with `<log_format>json</log_format>`, and append `wazuh/waf-rules.xml` to the manager's `local_rules.xml`.

## Lessons learned

- **Signature-based detection has a real, well-understood blind spot:** anything that doesn't match a known pattern gets through. Rate limiting exists precisely to cover the gap signatures can't abuse that looks clean on a per-request basis but is obviously wrong in aggregate.
- **Decode before you inspect.** Any filter that checks raw, still-encoded input can be bypassed by encoding the payload a lesson that generalizes well beyond this one project.
- **Structured logging pays for itself immediately.** Switching from a human-readable log line to JSON turned a fragile, regex-based SIEM integration into a "just declare `log_format json`" integration  zero custom decoder needed, matching the pattern already proven in the honeypot project.

## What's next

- Strip the duplicate `Server`/`Date` headers currently leaking that a Python proxy sits in front of Apache
- Expand the rule set (command injection, CSRF token checks)
- Feed Wazuh alerts into the AI-powered SOC bot project for automated triage
