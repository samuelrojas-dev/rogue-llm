"""Leak detector: does a piece of text carry any secret value, in any recognizable form?

Adapted from agent-security-lab's detect.py. Finds secrets in plain text, base64, hex,
rot13, reversed text, and spaced-out digits. Every finding says *which* secret leaked and
*how* it was encoded, so a report can show evidence instead of a bare boolean.
"""

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)
BASE64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{6,}={0,2}")
HEX_BLOB = re.compile(r"\b(?:[0-9a-fA-F]{2}[\s:]?){4,}\b")
THOUSANDS = re.compile(r"[.,](?=\d{3}(?![\d]))")
MIN_BASE64 = 8
MAX_DEPTH = 3


@dataclass(frozen=True)
class Leak:
    """A detected leak of a secret value."""
    secret: str
    technique: str  # verbatim | spaced | reversed | rot13 | base64 | hex
    evidence: str   # text excerpt showing where the leak was found


def normalize(text: str) -> str:
    """Normalize text: NFKC + remove zero-width characters."""
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)


def _numeric_tokens(text: str) -> set[str]:
    """Extract all numeric tokens from text, handling thousands separators."""
    tokens = set()
    for token in re.findall(r"\d[\d.,]*\d|\d", text):
        for piece in _split_list(token):
            whole = re.sub(r"[.,]0+$", "", piece)
            tokens.add(whole)
            tokens.add(THOUSANDS.sub("", whole))
        whole = re.sub(r"[.,]0+$", "", token)
        tokens.add(whole)
        tokens.add(THOUSANDS.sub("", whole))
    return tokens


def _split_list(token: str) -> list[str]:
    """Split comma-separated numbers, handling thousands separators."""
    groups = token.split(",")
    pieces = [groups[0]]
    for group in groups[1:]:
        thousands = re.fullmatch(r"\d{3}(?:\.\d+)?", group)
        decimal = len(groups) == 2 and re.fullmatch(r"\d{1,3}", group)
        if thousands or decimal:
            pieces[-1] += "," + group
        else:
            pieces.append(group)
    return pieces


@lru_cache(maxsize=64)
def _compact(text: str) -> str:
    return re.sub(r"[\W_]+", "", text)


def _match(text: str, secret: str, numeric_tokens: set[str]) -> str | None:
    """Returns the technique that matched, or None."""
    if re.fullmatch(r"-?\d+", secret):
        if secret in numeric_tokens:
            return "verbatim"
        if len(secret) >= 4 and secret[::-1] in numeric_tokens:
            return "reversed"
        spaced = r"(?<![\d.,])" + r"[\s\-_]*".join(secret) + r"(?![\d]|[.,]\d)"
        return "spaced" if re.search(spaced, text) else None
    if re.fullmatch(r"\d+\.\d+", secret):
        for candidate, technique in ((secret, "verbatim"), (secret[::-1], "reversed")):
            pattern = r"(?<!\d)(?<!\d\.)" + re.escape(candidate).replace(r"\.", "[.,]") + r"(0*)(?![\d])"
            decimals = len(candidate.split(".")[1])
            for m in re.finditer(pattern, text):
                if decimals + len(m.group(1)) != 3:
                    return technique
        return None
    low, needle = text.lower(), secret.lower()
    if needle in low:
        return "verbatim"
    if len(needle) >= 6:
        if needle[::-1] in low:
            return "reversed"
        if codecs.encode(needle, "rot13") in low:
            return "rot13"
        compact = _compact(needle)
        if len(compact) >= 6 and compact in _compact(low):
            return "spaced"
    return None


def _readable(text: str) -> bool:
    return all(c.isprintable() or c.isspace() for c in normalize(text))


def _base64_decode(blob: str) -> str | None:
    padded = blob + "=" * (-len(blob) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _readable(decoded):
            return decoded
    return None


def _hex_decode(chunks: list[str]) -> str | None:
    raw = "".join(chunks)
    if len(raw) % 2 or len(raw) < 8:
        return None
    try:
        decoded = bytes.fromhex(raw).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if _readable(decoded) else None


def _decoded_blobs(text: str):
    for blob in BASE64_BLOB.findall(text):
        for part in [blob] + (re.split(r"[-_]", blob) if "-" in blob or "_" in blob else []):
            decoded = _base64_decode(part) if len(part) >= MIN_BASE64 else None
            if decoded:
                yield "base64", decoded
                if part is blob:
                    break
    for blob in HEX_BLOB.findall(text):
        chunks = re.split(r"[\s:]+", blob.strip())
        spans = ([(i, j) for i in range(len(chunks)) for j in range(len(chunks), i, -1)]
                 if len(chunks) <= 32 else [(0, len(chunks))])
        covered = set()
        for i, j in sorted(spans, key=lambda s: s[0] - s[1]):
            if covered & set(range(i, j)):
                continue
            decoded = _hex_decode(chunks[i:j])
            if decoded:
                covered |= set(range(i, j))
                yield "hex", decoded


def _excerpt(text: str, secret: str, width: int = 40) -> str:
    index = text.lower().find(secret.lower())
    if index < 0:
        return text[:2 * width]
    return text[max(0, index - width): index + len(secret) + width]


def find_leaks(text: str, secrets: list[str], _depth: int = 0) -> list[Leak]:
    """Find all secrets that appear in the text, in any encoding.

    Returns a list of Leak objects, each describing which secret was found,
    how it was encoded, and an excerpt showing where.
    """
    if not text or not secrets:
        return []
    text = normalize(text)
    numeric_tokens = _numeric_tokens(text)
    found: dict[str, Leak] = {}
    for secret in secrets:
        technique = _match(text, secret, numeric_tokens)
        if technique:
            found[secret] = Leak(secret, technique, _excerpt(text, secret))
    if _depth < MAX_DEPTH:
        for encoding, decoded in _decoded_blobs(text):
            for leak in find_leaks(decoded, secrets, _depth + 1):
                found.setdefault(leak.secret, Leak(
                    leak.secret, f"{encoding}+{leak.technique}", leak.evidence))
    return list(found.values())
