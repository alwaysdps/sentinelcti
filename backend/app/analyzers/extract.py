"""Bounded, linear-time extraction of indicators from untrusted text.

WHY THIS MODULE EXISTS
----------------------
Regexes run over attacker-controlled bytes are a denial-of-service primitive.
The original domain pattern here -- `(?:label\\.)+tld` -- was measured at O(n^2)
on input like "a.a.a.a...": 16 KB took 4.5 s, so the analyzer's 2 MB scan
window would have taken hours. A ~1 KB upload could therefore hang a worker
indefinitely. That is not a hypothetical; it was reproduced before this module
was written.

The fix is structural rather than a cleverer regex:

1. **Tokenise first.** Split on characters that cannot appear in the indicator,
   then validate each token with an *anchored* pattern. Anchoring means one
   match attempt per token instead of one per character offset, which is what
   turns the quadratic scan linear.
2. **Bound every token.** A hostname cannot exceed 253 characters (RFC 1035),
   so a 2 MB run of "a.a.a." is discarded on a length check before any regex
   touches it.
3. **Cap the result count.** Extraction stops once the caller's limit is hit;
   a file full of unique domains cannot balloon the stored report.
4. **Respect a deadline.** Every loop checks a monotonic budget, so even an
   input that defeats all of the above degrades into a truncated -- and
   explicitly reported -- analysis rather than a hung request.

Everything here only ever *reads* text. Nothing is decoded, resolved, fetched
or executed.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

# --- Bounds ---------------------------------------------------------------
MAX_HOSTNAME_LENGTH = 253  # RFC 1035
MAX_URL_LENGTH = 2048
MAX_EMAIL_LENGTH = 254  # RFC 5321
MAX_PATH_LENGTH = 260  # traditional Windows MAX_PATH
DEFAULT_LIMIT = 50


class AnalysisBudget:
    """Cooperative wall-clock deadline for a single analysis.

    A worker thread cannot be forcibly killed, so the timeout has to be
    cooperative: long-running loops ask `expired` between units of work and
    stop early. Truncation is recorded so the report can say the sweep was cut
    short instead of quietly presenting partial results as complete.
    """

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._deadline = time.monotonic() + seconds
        self.truncated = False

    @property
    def expired(self) -> bool:
        if time.monotonic() >= self._deadline:
            self.truncated = True
            return True
        return False

    @property
    def remaining(self) -> float:
        return max(0.0, self._deadline - time.monotonic())


# --- Tokenisation ---------------------------------------------------------
# Split on anything that cannot occur inside a hostname. A run with no such
# separator is a single oversized token and gets rejected on length alone.
_HOST_TOKEN_SPLIT = re.compile(r"[^A-Za-z0-9._-]+")
_URL_TOKEN_SPLIT = re.compile(r"[\s\"'<>()\[\]{},;]+")

# Anchored validators. `fullmatch` against a length-capped token means one
# bounded attempt per token, never a scan across the whole blob.
_HOSTNAME = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}",
    re.IGNORECASE,
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}")
_URL = re.compile(r"https?://[^\s\"'<>\\)\]]{4,}", re.IGNORECASE)
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
# Anchored per token: drive letter, separator, then path characters. Written
# without a nested quantifier so there is no ambiguity for the engine to
# backtrack through.
_WINDOWS_PATH = re.compile(r"[A-Za-z]:[\\/][^\\/:*?\"<>|\r\n]*(?:[\\/][^\\/:*?\"<>|\r\n]*)*")
_WINDOWS_PATH_HINT = re.compile(r"[A-Za-z]:[\\/]")


@dataclass
class ExtractedIndicators:
    urls: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    windows_paths: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "urls": self.urls,
            "ipv4": self.ipv4,
            "emails": self.emails,
            "domains": self.domains,
            "windows_paths": self.windows_paths,
        }

    @property
    def total(self) -> int:
        return len(self.urls) + len(self.ipv4) + len(self.emails) + len(self.domains)


def _ordered_unique(values: list[str], limit: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def extract_urls(text: str, *, limit: int = DEFAULT_LIMIT, budget: AnalysisBudget | None = None) -> list[str]:
    found: list[str] = []
    for match in _URL.finditer(text):
        if budget and budget.expired:
            break
        value = match.group()[:MAX_URL_LENGTH]
        found.append(value)
        if len(found) >= limit * 4:  # over-collect a little, dedupe below
            break
    return _ordered_unique(found, limit)


def extract_ipv4(text: str, *, limit: int = DEFAULT_LIMIT, budget: AnalysisBudget | None = None) -> list[str]:
    found: list[str] = []
    for match in _IPV4.finditer(text):
        if budget and budget.expired:
            break
        found.append(match.group())
        if len(found) >= limit * 4:
            break
    return _ordered_unique(found, limit)


def extract_hostnames_and_emails(
    text: str,
    *,
    limit: int = DEFAULT_LIMIT,
    budget: AnalysisBudget | None = None,
) -> tuple[list[str], list[str]]:
    """Pull domains and e-mail addresses in one tokenised pass.

    Both are validated against length-capped tokens, which is what keeps this
    linear in the size of the input.
    """
    domains: list[str] = []
    emails: list[str] = []
    checked = 0

    for token in _HOST_TOKEN_SPLIT.split(text):
        # Cheap rejects first: the length cap is what defuses the pathological
        # "a.a.a.a..." case, since no legal hostname is that long.
        if not token or len(token) > MAX_HOSTNAME_LENGTH:
            continue

        checked += 1
        # The budget is consulted periodically rather than per token: the check
        # itself is a syscall-ish operation and would otherwise dominate.
        if budget and checked % 256 == 0 and budget.expired:
            break

        candidate = token.strip(".").lower()
        if len(candidate) < 4 or "." not in candidate:
            continue

        if _HOSTNAME.fullmatch(candidate):
            domains.append(candidate)
            if len(domains) >= limit * 4:
                break

    # E-mails need the '@', which the hostname tokeniser splits on, so they get
    # their own bounded pass over separator-delimited tokens.
    for token in _URL_TOKEN_SPLIT.split(text):
        if not token or len(token) > MAX_EMAIL_LENGTH or "@" not in token:
            continue
        if budget and budget.expired:
            break
        match = _EMAIL.fullmatch(token.strip(".,;:"))
        if match:
            emails.append(match.group().lower())
            if len(emails) >= limit * 2:
                break

    return _ordered_unique(domains, limit), _ordered_unique(emails, limit)


def extract_windows_paths(
    text: str, *, limit: int = 25, budget: AnalysisBudget | None = None
) -> list[str]:
    """Anchored per-token matching; no nested quantifier to backtrack through."""
    found: list[str] = []
    for token in _URL_TOKEN_SPLIT.split(text):
        if not token or len(token) > MAX_PATH_LENGTH:
            continue
        if budget and budget.expired:
            break
        if not _WINDOWS_PATH_HINT.match(token):
            continue
        match = _WINDOWS_PATH.fullmatch(token)
        if match:
            found.append(match.group())
            if len(found) >= limit * 2:
                break
    return _ordered_unique(found, limit)


def extract_all(
    text: str, *, limit: int = DEFAULT_LIMIT, budget: AnalysisBudget | None = None
) -> ExtractedIndicators:
    urls = extract_urls(text, limit=limit, budget=budget)
    ipv4 = extract_ipv4(text, limit=limit, budget=budget)
    domains, emails = extract_hostnames_and_emails(text, limit=limit, budget=budget)
    paths = extract_windows_paths(text, budget=budget)

    # A URL already reports its host; listing it again as a bare domain is
    # noise in the report rather than a second observation.
    url_hosts = {u.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower() for u in urls}
    domains = [d for d in domains if d not in url_hosts]

    return ExtractedIndicators(
        urls=urls, ipv4=ipv4, emails=emails, domains=domains, windows_paths=paths
    )
