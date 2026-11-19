# PhishLens

Upload a suspicious email. Get the evidence, work the case, make the call.

PhishLens is a defensive triage workbench for the first job a SOC analyst
does with a suspicious email: work out what it actually is before anyone
clicks anything. Upload `.eml` files or paste raw source, and PhishLens
returns an evidence report - every red flag with its proof and why it
matters - stored as a case you can search, annotate, overrule and export.

**PhishLens never opens, resolves or fetches the links in an email.**
Every finding comes from the message itself.

![The PhishLens workbench](https://github.com/user-attachments/assets/f17e1ac1-7730-4dcf-b946-78b84b34e160)

## Interface and accessibility

The workbench is a dark navigation rail (case queue, search, filters) beside
a light evidence canvas. A selected case leads with the verdict and a
severity summary, then the evidence; full metadata sits behind a Case
details disclosure. On small screens the queue and the case are separate
views with a back control between them.

- Contrast: the text/background palette pairs were checked programmatically
  against the WCAG contrast formula, and all pass AA (>= 4.5:1). This is a
  palette contrast check, not a full WCAG conformance audit.
- Keyboard: every action is a native button, link, select, input or
  details/summary; the tab strip supports arrow keys, Home and End; the
  dialog closes with Escape and returns focus; the drop zone is a real
  button target.
- Scores are always labelled as heuristic, never as calibrated
  probabilities.

## What it does

### Detection engine: 24 named, documented rules

Every signal is a rule with a stable ID, a written rationale and unit
tests - not an anonymous score. Categories:

- **Headers** - Reply-To and Return-Path domain mismatches against the From
  domain (the business-email-compromise shape).
- **Authentication** - SPF / DKIM / DMARC outcomes **as recorded by the
  receiving server** in Authentication-Results. When nothing was recorded,
  PhishLens says authentication is unknown - never silently "passed".
- **Links** (extracted, never visited) - anchor text that lies about the
  destination, raw IP hosts, `@`-sign host hiding, punycode, shorteners,
  high-risk TLDs, padded subdomains.
- **Lookalike domains** - brand names inside someone else's domain,
  leetspeak (`paypa1`), one-character typos. Covers global brands plus the
  South African banks, SARS and Takealot.
- **Language** - pressure phrases and credential bait.
- **Attachments** - risky filenames and double extensions, plus **magic-byte
  content inspection**: a `statement.pdf` whose bytes are a Windows
  executable is caught by the file itself, not its name. SHA-256 and MD5
  are computed for every attachment. Contents are never executed, rendered
  or decompressed.
- **Route** - the Received chain parsed into relay hops: missing chains,
  out-of-order timestamps, unusually slow hops.

Where a mapping is direct, rules carry their MITRE ATT&CK reference
(T1566.001/.002). Rules are exposed at `GET /api/rules` so the tool
documents itself.

### Analyst workflow

- **Cases** - every analysis is persisted locally (SQLite) with its full
  evidence. Search, filter by verdict, come back later.
- **Batch triage** - upload several `.eml` files at once; each becomes a
  severity-badged case in the queue.
- **Analyst verdict** - overrule the heuristic with your own call and a
  reason; both are recorded in the case's note trail.
- **Notes** - a free-text trail of what you checked.
- **Case status and aging** - every case moves through New, In review and
  Closed, and the queue shows each case's status and age, so nothing sits
  unreviewed without being visible.
- **Related cases** - the Related tab groups cases that share a sender
  domain, link host or attachment hash, so a cluster can be reviewed
  together. Shared infrastructure is a triage hint, not proof of a common
  sender or campaign.
- **Export** - a self-contained, print-ready HTML report (no scripts, no
  live links, everything escaped) and a defanged IOC list for tickets and
  block lists.
- **Incident handoff** - one click copies a plain-text summary (verdict,
  findings, defanged indicators, analyst call) ready to paste into a
  ticket or chat. Nothing is sent anywhere; the handoff never leaves the
  clipboard.

### Indicators of compromise

Domains, URLs, IP literals, sender addresses and file hashes, deduplicated
and shown with **defang/refang** (`hxxps://paypal[.]com...`) so indicators
are safe to paste into chat, tickets and block lists.

## Run it

```bash
pip install -r requirements.txt
uvicorn phishlens.api:app
```

Open http://127.0.0.1:8000. The app binds to localhost by default and
talks to no external services.

### CLI

```bash
python -m phishlens suspicious.eml              # JSON report
python -m phishlens suspicious.eml --iocs       # defanged indicators only
python -m phishlens suspicious.eml --report out.html
```

### Docker

```bash
docker build -t phishlens .
docker run --rm -p 127.0.0.1:8000:8000 -v phishlens-data:/data phishlens
```

Publish the port on localhost only: the case store has no authentication,
and every stored email is reachable by whoever can reach the port.

## Configuration

| Variable       | Default                  | Purpose                  |
| -------------- | ------------------------ | ------------------------ |
| `PHISHLENS_DB` | `~/.phishlens/cases.db`  | Where cases are stored   |

## Tests and evaluation

```bash
python -m pytest tests/ -q     # 60 tests
python scripts/evaluate.py     # fixture-corpus report
```

Tests cover the parser, every rule, the route parser, IOC extraction, the
case store, the export renderer and the API.

`evaluate.py` scores the engine against the fixture corpus in
`tests/fixtures` - six hand-written synthetic messages labelled by
filename. It exists to catch regressions in development. **Precision on
six synthetic fixtures is not real-world accuracy**; a credible number
needs a large, current, labelled corpus of real mail, which this project
deliberately does not ship.

## Honest limits

- Authentication findings repeat what the receiving server recorded.
  PhishLens does not re-verify SPF, DKIM or DMARC, and a hand-pasted
  message with no Authentication-Results header has no authentication
  evidence at all.
- The verdict is triage, not truth. `no_strong_signals` means no strong
  signals were found, not that the email is safe. The analyst override
  exists because the human decides.
- It does not detonate attachments or follow redirects. That is deliberate:
  the box analyzing the email should not be the box opening it.
- The brand list is short by design; it is not a threat-intel feed.
- The score is a documented heuristic (high 30, medium 12, low 4, cap
  100), not a calibrated probability.
- Cases are stored unencrypted in a local SQLite file, protected only by
  operating-system file permissions.

## Stack

Python 3.10+, FastAPI, vanilla JS/CSS frontend (no build step), SQLite
(stdlib), pytest. No paid services, no external API calls, no tracking.

## CI

GitHub Actions runs ruff, the test suite and the fixture evaluation on
every push and pull request (Python 3.10 and 3.12).
