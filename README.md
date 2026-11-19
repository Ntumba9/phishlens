# PhishLens

Upload a suspicious email. Get the evidence, not just a verdict.

PhishLens is a defensive triage tool for the first job a SOC analyst does
with a suspicious email: work out what it actually is before anyone clicks
anything. You upload an `.eml` file or paste the raw message source, and
PhishLens returns a report listing every red flag it found, with the proof
for each one, so a human can make the call.

**PhishLens never opens, resolves or fetches the links in an email.** Every
finding comes from the message itself.

## What it checks

**Headers**
- From vs Reply-To domain mismatch (replies routed to the attacker's domain)
- From vs Return-Path (bounce address) mismatch
- SPF / DKIM / DMARC results recorded by the receiving server
- Missing Received chain or missing authentication results

**Links** (extracted, never visited)
- Anchor text that shows one domain but links to another
- Raw IP addresses instead of domain names
- URLs hiding their real host behind an `@` sign
- Punycode hosts (`xn--`), the classic lookalike-character trick
- URL shorteners that hide the destination
- High-risk TLDs and heavily padded subdomains

**Lookalike domains**
- Brand names inside someone else's domain (`paypal.com.account-verify.top`)
- Leetspeak that reads as a brand (`secure-paypa1.top` reads as "paypal")
- One-character typos of major brands, including South African banks and SARS

**Language**
- Pressure phrases ("account suspended", "verify within 24 hours")
- Credential bait ("enter your password", "confirm your card")

**Attachments** (filenames only, contents never opened)
- Executables and scripts, including double extensions (`invoice.pdf.exe`)
- HTML/SVG attachments used to smuggle fake login pages
- Archives and macro-enabled documents

## Scoring

Findings carry severities (high 30, medium 12, low 4). The score caps at 100.

| Score | Verdict |
| ----- | ------- |
| 50+   | `likely_phish` |
| 20-49 | `suspicious` |
| <20   | `no_strong_signals` |

The verdict is triage, not truth. `no_strong_signals` means no strong
signals were found, not that the email is safe. The reasons always ship
with the verdict so an analyst can overrule it.

## Run it

```bash
pip install -r requirements.txt
uvicorn phishlens.api:app
```

Open http://127.0.0.1:8000, upload an `.eml` file or paste raw source.

The app binds to localhost by default and talks to no external services.

### CLI

```bash
python -m phishlens suspicious.eml
```

Prints the report as JSON.

## Tests

```bash
python -m pytest tests/ -q
```

20 tests cover the parser, every check, the scoring, and the API, against a
synthetic phishing fixture (fake PayPal scare mail) and a legitimate
newsletter fixture. The phishing fixture scores `likely_phish`; the
legitimate one scores `no_strong_signals`.

## Honest limits

- Header authentication results are only as good as the receiving server
  that recorded them. A hand-crafted paste with no real Received chain
  loses that evidence.
- The brand list is short by design. It catches the big global brands and
  the major South African ones; it is not a threat-intel feed.
- It does not detonate attachments or follow redirects. That is deliberate:
  the box analyzing the email should not be the box opening it.
- Deterministic checks miss novel lures. A human still makes the call.

## Roadmap

- Optional RDAP domain-age lookups (off by default, registry data only)
- Optional AI-drafted analyst summary on top of the deterministic evidence
- Verdict explanations tuned for junior analysts learning triage

## Stack

Python 3.10+, FastAPI, vanilla JS frontend, pytest. Standard-library email
parsing. No paid services, no external API calls, no build step.
