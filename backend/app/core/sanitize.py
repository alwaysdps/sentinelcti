"""Neutralising untrusted text before it is stored, logged or displayed.

Content pulled out of a submitted sample is attacker-authored by definition.
It leaves this process through three channels, each with its own failure mode:

* **The API response → the browser.** React escapes interpolated text, so
  markup cannot execute. What it does *not* stop is a bidirectional override
  (U+202E) silently reversing how the rest of a line renders, which is the same
  trick the file analyzer flags in filenames. Stripping the control characters
  here means a report can never be made to misrepresent its own contents.
* **The application log.** ANSI escape sequences and carriage returns let
  attacker text repaint or forge lines in an operator's terminal.
* **The database.** NUL bytes are rejected outright by PostgreSQL text columns,
  so leaving them in would turn a hostile sample into a failed insert.

Defanging (hxxp://, 1.2.3[.]4) is applied to the *display* copy of network
indicators so that no report -- or anything pasted out of one -- is one
mis-click away from resolving hostile infrastructure.
"""

from __future__ import annotations

import re
import unicodedata

MAX_DISPLAY_STRING = 200

# Bidi overrides/embeddings, zero-width characters and other invisible
# formatting. All are legitimate in some scripts but have no business in an
# extracted artefact, where their only effect is to deceive the reader.
_INVISIBLE = {
    "​", "‌", "‍", "‎", "‏",
    "‪", "‫", "‬", "‭", "‮",
    "⁦", "⁧", "⁨", "⁩",
    "﻿", "­",
}

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[@-Z\\-_]")


def scrub(value: str, *, max_length: int = MAX_DISPLAY_STRING) -> str:
    """Return `value` safe to store, log and render. Content is preserved."""
    if not value:
        return ""

    text = _ANSI_ESCAPE.sub("", value)

    cleaned: list[str] = []
    for char in text:
        if char in _INVISIBLE:
            continue
        category = unicodedata.category(char)
        # Cc = control, Cf = format, Cs = surrogate, Co/Cn = private/unassigned.
        # Tab is the one control character worth keeping for readability.
        if category in ("Cc", "Cf", "Cs", "Co", "Cn"):
            if char == "\t":
                cleaned.append(" ")
            continue
        cleaned.append(char)

    result = "".join(cleaned).strip()
    if len(result) > max_length:
        result = result[: max_length - 1] + "…"
    return result


def scrub_all(values: list[str], *, max_length: int = MAX_DISPLAY_STRING) -> list[str]:
    return [scrubbed for value in values if (scrubbed := scrub(value, max_length=max_length))]


# Long enough for a full URL; the point is neutralising characters, not
# shortening values that are legitimately long.
MAX_STORED_STRING = 2048


def scrub_structure(value, *, max_length: int = MAX_STORED_STRING):
    """Recursively neutralise every string inside a nested structure.

    Applied once at the persistence boundary rather than in each analyzer.
    Analyzers embed submitted values into finding titles, descriptions and
    technical details -- so a URL analyzer quoting the host back into "Valid
    hostname syntax '<host>'" would otherwise carry a bidi override straight
    into the report. Doing this in one place means a new analyzer inherits the
    protection instead of having to remember it.

    Keys are left alone: they are analyzer-authored identifiers, never
    submitter input.
    """
    if isinstance(value, str):
        return scrub(value, max_length=max_length)
    if isinstance(value, dict):
        return {key: scrub_structure(item, max_length=max_length) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub_structure(item, max_length=max_length) for item in value]
    return value


def defang(value: str) -> str:
    """Render a network indicator non-clickable and non-resolvable.

    Standard CTI convention, applied to the display copy only -- the analysed
    value is stored verbatim so nothing is lost.
    """
    if not value:
        return value
    out = re.sub(r"^http://", "hxxp://", value, flags=re.IGNORECASE)
    out = re.sub(r"^https://", "hxxps://", out, flags=re.IGNORECASE)
    # Only the dots inside the authority are neutralised; a path keeps its dots
    # so filenames stay readable.
    if "://" in out:
        scheme, _, rest = out.partition("://")
        authority, slash, path = rest.partition("/")
        return f"{scheme}://{authority.replace('.', '[.]')}{slash}{path}"
    return out.replace(".", "[.]")


def defang_all(values: list[str]) -> list[str]:
    return [defang(value) for value in values]
