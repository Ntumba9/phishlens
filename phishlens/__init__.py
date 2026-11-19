"""PhishLens: defensive phishing triage for uploaded emails.

Parses a suspicious email (.eml or pasted raw source), inspects headers,
links and language, and produces an evidence report for a human analyst.

PhishLens never visits the links it finds in an email.
"""

__version__ = "0.1.0"
