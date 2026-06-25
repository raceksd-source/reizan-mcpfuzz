"""Normalization and hidden-content detection helpers."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
}

HYPHEN_CHARS = {
    "\u2010": "-",
    "\u2011": "-",
    "\u2012": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2015": "-",
    "\u2043": "-",
    "\u2212": "-",
}

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


@dataclass(frozen=True)
class HiddenSpan:
    start: int
    end: int
    span: str
    message: str


@dataclass(frozen=True)
class NormalizedText:
    text: str
    index_map: tuple[int, ...]

    def original_span(self, start: int, end: int, original: str) -> tuple[int, int]:
        if not self.index_map or start >= end:
            return 0, 0
        bounded_start = max(0, min(start, len(self.index_map) - 1))
        bounded_end = max(0, min(end - 1, len(self.index_map) - 1))
        return self.index_map[bounded_start], self.index_map[bounded_end] + 1


def normalize_with_map(text: str) -> NormalizedText:
    """Apply NFKC and CVE-style hyphen/zero-width translation with a span map."""

    output: list[str] = []
    index_map: list[int] = []
    for index, char in enumerate(text):
        if char in ZERO_WIDTH_CHARS:
            continue
        normalized = unicodedata.normalize("NFKC", char)
        for normalized_char in normalized:
            if normalized_char in ZERO_WIDTH_CHARS:
                continue
            translated = HYPHEN_CHARS.get(normalized_char, normalized_char)
            output.append(translated)
            index_map.append(index)
    return NormalizedText("".join(output), tuple(index_map))


def hidden_spans(text: str, signature: str) -> tuple[HiddenSpan, ...]:
    if signature == "zero_width":
        return tuple(_zero_width_spans(text))
    if signature == "ansi_escape":
        return tuple(_ansi_spans(text))
    if signature in {"unicode_confusable", "unicode_hyphen_or_nfkc"}:
        return tuple(_unicode_confusable_spans(text))
    return ()


def _zero_width_spans(text: str) -> list[HiddenSpan]:
    spans: list[HiddenSpan] = []
    for index, char in enumerate(text):
        name = ZERO_WIDTH_CHARS.get(char)
        if name is None:
            continue
        spans.append(HiddenSpan(index, index + 1, char, f"hidden zero-width character: {name}"))
    return spans


def _ansi_spans(text: str) -> list[HiddenSpan]:
    spans: list[HiddenSpan] = []
    for match in ANSI_ESCAPE_RE.finditer(text):
        spans.append(HiddenSpan(match.start(), match.end(), match.group(0), "ANSI escape sequence"))
    return spans


def _unicode_confusable_spans(text: str) -> list[HiddenSpan]:
    spans: list[HiddenSpan] = []
    for index, char in enumerate(text):
        if char in ZERO_WIDTH_CHARS:
            continue
        replacement = HYPHEN_CHARS.get(char)
        normalized = unicodedata.normalize("NFKC", char)
        if replacement is not None:
            message = f"unicode hyphen/lookalike {char_name(char)} normalizes to '-'"
        elif normalized != char and _is_prompt_relevant_confusable(char, normalized):
            message = f"unicode lookalike {char_name(char)} normalizes to {normalized!r}"
        else:
            continue
        spans.append(HiddenSpan(index, index + 1, char, message))
    return spans


def _is_prompt_relevant_confusable(char: str, normalized: str) -> bool:
    if char.isascii():
        return False
    if any(part.isascii() and (part.isalnum() or part in {"-", "_", ":", "/", "."}) for part in normalized):
        return True
    return False


def char_name(char: str) -> str:
    try:
        name = unicodedata.name(char)
    except ValueError:
        name = "UNNAMED"
    return f"U+{ord(char):04X} {name}"
