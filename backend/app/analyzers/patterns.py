"""Detection patterns and reference lists used across analyzers.

Kept in one module so the heuristics are reviewable as a set rather than
scattered through analysis code. Every list here is a *heuristic*: presence
raises suspicion, it never proves malice. The risk engine weights them
accordingly and the report always names which pattern fired.
"""

from __future__ import annotations

import re

# --- Structural extraction ------------------------------------------------
#
# NOTE: indicator extraction (URLs, IPs, domains, e-mails, paths) lives in
# `extract.py`, not here. Those patterns run over attacker-controlled bytes,
# and the naive whole-blob versions that used to sit in this module were
# measured at O(n^2) -- a ~1 KB crafted upload could hang a worker for hours.
# `extract.py` tokenises and length-bounds before matching, which is what makes
# the sweep linear. Only patterns applied to *bounded* input remain here.

# Base64 run long enough that a false positive on prose is unlikely. A single
# character class with a lower bound: linear, no nested quantifier.
BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}")
HEX_BLOB_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){24,}\b")

HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]+$")

# --- Suspicious content patterns -----------------------------------------
# (regex, code, human title, points, ATT&CK ids)
SUSPICIOUS_CONTENT_PATTERNS: list[tuple[re.Pattern[str], str, str, int, tuple[str, ...]]] = [
    (re.compile(r"powershell(?:\.exe)?\b", re.I), "ps_invocation",
     "PowerShell invocation", 12, ("T1059", "T1059.001")),
    (re.compile(r"-enc(?:odedcommand)?\b|-e\s+[A-Za-z0-9+/]{20,}", re.I), "ps_encoded_command",
     "PowerShell encoded command flag", 20, ("T1059.001", "T1027")),
    (re.compile(r"\b(?:iex|invoke-expression)\b", re.I), "iex",
     "Dynamic expression execution (IEX)", 18, ("T1059.001", "T1140")),
    (re.compile(r"invoke-webrequest|downloadstring|downloadfile|start-bitstransfer", re.I),
     "remote_download", "Remote content download primitive", 18, ("T1105", "T1071.001")),
    (re.compile(r"\bcertutil\b.*-(?:decode|urlcache)", re.I), "certutil_abuse",
     "certutil used for download/decode", 20, ("T1140", "T1218", "T1105")),
    (re.compile(r"\b(?:curl|wget)\b\s+https?://", re.I), "cli_fetch",
     "Command-line remote fetch", 12, ("T1105",)),
    (re.compile(r"\bcmd(?:\.exe)?\s*/c\b", re.I), "cmd_exec",
     "Windows command shell execution", 12, ("T1059.003",)),
    (re.compile(r"/bin/(?:ba|z|k)?sh\b|\bsh\s+-c\b", re.I), "unix_shell",
     "Unix shell execution", 10, ("T1059.004",)),
    (re.compile(r"\bbase64\s+(?:-d|--decode)\b|FromBase64String", re.I), "base64_decode",
     "Base64 decode routine", 15, ("T1140", "T1027")),
    (re.compile(r"reg(?:\.exe)?\s+add\b|HKCU\\\\?Software\\\\?Microsoft\\\\?Windows\\\\?CurrentVersion\\\\?Run", re.I),
     "run_key", "Registry Run-key persistence pattern", 20, ("T1547.001", "T1112")),
    (re.compile(r"schtasks(?:\.exe)?\b|\bcrontab\b\s+-", re.I), "scheduled_task",
     "Scheduled task/job creation", 15, ("T1053",)),
    (re.compile(r"vssadmin\b.*delete\s+shadows|wbadmin\b.*delete|bcdedit\b.*recoveryenabled", re.I),
     "inhibit_recovery", "Shadow-copy / recovery destruction command", 25, ("T1490",)),
    (re.compile(r"\bmshta\b|\brundll32\b|\bregsvr32\b.*scrobj", re.I), "lolbin",
     "Living-off-the-land binary proxy execution", 18, ("T1218",)),
    (re.compile(r"eval\s*\(\s*(?:atob|base64_decode|unescape)\s*\(", re.I), "script_eval_decode",
     "Script eval over decoded payload", 20, ("T1027", "T1140")),
    (re.compile(r"document\.write\s*\(\s*unescape\s*\(", re.I), "js_obfuscation",
     "Obfuscated script writer", 15, ("T1027",)),
    (re.compile(r"\bAuto(?:Open|Close|Exec)\b|Workbook_Open|Document_Open", re.I), "macro_autorun",
     "Office macro auto-execution entry point", 20, ("T1204.002",)),
    (re.compile(r"\bnet\s+user\b.*\/add|\bnet\s+localgroup\b.*administrators", re.I), "account_add",
     "Local account/privilege modification", 18, ("T1059.003",)),
]

# --- URL / domain heuristics ---------------------------------------------
# TLDs with historically high abuse ratios and cheap/free registration. Being
# on this list means "warrants a closer look", not "malicious".
SUSPICIOUS_TLDS = {
    "zip", "mov", "cam", "top", "xyz", "gq", "cf", "ml", "ga", "tk", "work",
    "click", "link", "country", "kim", "loan", "download", "racing", "review",
    "science", "stream", "party", "date", "faith", "win", "bid", "rest", "quest",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly", "s.id",
}

# Brand-impersonation bait: a login-ish keyword in the *host* is a classic
# credential-phishing tell, because the real brand never needs it there.
PHISHING_KEYWORDS = {
    "login", "signin", "secure", "account", "verify", "verification", "update",
    "confirm", "banking", "webscr", "password", "credential", "wallet",
    "unlock", "suspended", "recovery", "authenticate", "billing", "invoice",
}

IMPERSONATED_BRANDS = {
    "paypal", "microsoft", "office365", "outlook", "apple", "icloud", "amazon",
    "google", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
    "dhl", "fedex", "ups", "hmrc", "irs", "binance", "coinbase", "metamask",
    "steam", "dropbox", "docusign", "adobe",
}

RISKY_FILE_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "ps1", "psm1", "hta", "jar", "msi", "dll", "lnk", "iso",
    "img", "apk", "reg", "cpl",
}

ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "bz2", "xz", "cab"}

DOUBLE_EXTENSION_RE = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt|csv)\.(?:"
    + "|".join(sorted(RISKY_FILE_EXTENSIONS))
    + r")$",
    re.IGNORECASE,
)

